using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
namespace Sli.Server.Notifications;

public sealed class TelegramSender(IHttpClientFactory clients,TelegramRequestState state)
{
    public async Task<TelegramOutcome> SendAsync(TelegramSettings settings,string text,CancellationToken ct)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);
        state.Begin(settings.Proxy,deadline);
        try {
            using var request=new HttpRequestMessage(HttpMethod.Post,$"https://api.telegram.org/bot{settings.Token}/sendMessage");
            request.Version=HttpVersion.Version11;request.VersionPolicy=HttpVersionPolicy.RequestVersionExact;
            request.Headers.ConnectionClose=true;
            request.Content=JsonContent.Create(new { chat_id=settings.Chat,text,link_preview_options=new {is_disabled=true},protect_content=true });
            using var response=await clients.CreateClient("notification-telegram").SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
            if((int)response.StatusCode is >=300 and <400)return new("telegram_rejected");
            int retry=0;
            if(response.Headers.TryGetValues("Retry-After",out var values)) {
                var value=values.FirstOrDefault();
                if(value is not null && value.Length is >0 and <=10 && value.All(char.IsAsciiDigit) && int.TryParse(value,out var parsed) && parsed>0)retry=parsed;
            }

            await using var stream=await response.Content.ReadAsStreamAsync(deadline.Token);
            using var buffer=new MemoryStream();byte[] chunk=new byte[4096];
            while(true) {int n=await stream.ReadAsync(chunk,deadline.Token);if(n==0)break;if(buffer.Length+n>32768)return new("telegram_outcome_unknown");buffer.Write(chunk,0,n);}
            return TelegramTransport.ParseResponse((int)response.StatusCode,new UTF8Encoding(false,true).GetString(buffer.ToArray()),retry);
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
        catch {return new(state.Connected ? "telegram_outcome_unknown" : "telegram_unavailable");}
    }
}
// Single sequential delivery loop owns this state. Connection pooling is disabled
// via Connection: close, so the filter marks this request only after TLS succeeds.
public sealed class TelegramRequestState : System.Net.IWebProxy
{
    private int connected;
    private Uri? proxy;
    private CancellationTokenSource? deadline;
    public bool Connected=>System.Threading.Volatile.Read(ref connected)!=0;
    public System.Net.ICredentials? Credentials {get=>null;set {if(value is not null)throw new NotSupportedException();}}
    public void Begin(string address,CancellationTokenSource timeout){proxy=address.Length==0?null:new Uri(address);deadline=timeout;System.Threading.Volatile.Write(ref connected,0);}
    public Uri GetProxy(Uri destination)=>proxy ?? destination;
    public bool IsBypassed(Uri host)=>proxy is null;
    public void MarkConnected(){System.Threading.Volatile.Write(ref connected,1);deadline?.CancelAfter(TimeSpan.FromSeconds(20));}
    public ValueTask<System.IO.Stream> ConnectedStream(System.Net.Http.SocketsHttpPlaintextStreamFilterContext context,CancellationToken ct)
    {MarkConnected();return ValueTask.FromResult(context.PlaintextStream);}
}
