using System.Security.Cryptography;
using System.Text;
using Sli.Server.Domains;

namespace Sli.Server.Auth.InitialOwner;

internal static class InitialOwnerPage
{
    // Exact frozen OWNER_SETUP_HTML; only the per-response CSP nonce is inserted.
    private const string Html = """
<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="referrer" content="no-referrer"><title>SLI — Create owner / Создание владельца</title>
<body><main><h1>SLI — Create owner / Создание владельца</h1>
<p>Account / Учётная запись: <strong>platform-owner</strong></p>
<p>Enter the one-time code from sli-setup and choose your password.<br>
Введите одноразовый код из sli-setup и задайте свой пароль.</p>
<form><label>Code / Код <input id="code" type="password" required autocomplete="off"></label><br>
<label>New password / Новый пароль <input id="password" type="password" minlength="12" maxlength="4096"
required autocomplete="new-password"></label><br>
<label>Repeat / Повтор <input id="repeat" type="password" required autocomplete="new-password"></label><br>
<button>Create owner / Создать владельца</button></form><p id="message" role="status"></p></main>
<script>document.querySelector("form").addEventListener("submit", async (event) => {
event.preventDefault(); const code=document.getElementById("code"), password=document.getElementById("password");
const message=document.getElementById("message"), button=document.querySelector("button");
if(password.value!==document.getElementById("repeat").value){message.textContent="Passwords differ / Пароли не совпадают";return;}
button.disabled=true;
try {const response=await fetch("/api/auth/bootstrap", {method:"POST", headers:{"Content-Type":"application/json"},
body:JSON.stringify({code:code.value,password:password.value})});
if(response.ok){location.replace("/app");}else{message.textContent="Cannot create owner: check code, password (12+ characters), or sign in if already created. / Проверьте код и пароль (от 12 символов); если владелец уже создан — войдите.";}
}catch{message.textContent="Connection failed / Нет соединения";}finally{code.value="";button.disabled=false;}
});</script></body></html>
""";

    public static Task SendAsync(HttpContext context)
    {
        string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        byte[] body = Encoding.UTF8.GetBytes(Html.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("<script>", "<script nonce=\"" + nonce + "\">", StringComparison.Ordinal));
        DomainHttp.ApplyHeaders(context, nonce: nonce);
        return Results.Bytes(body, "text/html; charset=utf-8").ExecuteAsync(context);
    }
}
