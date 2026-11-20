using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.Agents.Consumer;

internal static partial class WorkstationLogonProjection
{
    private static string BuildTaskGroupAudit(int id,IReadOnlyDictionary<string,string?> data,JsonObject roles,JsonObject facts,JsonObject quality)
    {
        void Put(string key,string? value){if(value is not null)facts[key]=value;}
        if(id is >=4698 and <=4702){
            string change=id switch{4698=>"created",4699=>"deleted",4700=>"enabled",4701=>"disabled",_=>"updated"};
            string? name=Text(data,"TaskName","TaskNamePath"),content=Text(data,"TaskContentNew","TaskContent");
            Put("task_name",name);if(content is not null&&Encoding.UTF8.GetByteCount(content)<=8192)Put("task_content",content);
            facts["task_change"]=change;Put("native_process_id",ProcessId(Text(data,"ClientProcessId")));
            Put("process_user_sid",ProcessText(data,"SubjectUserSid",512));Put("process_user_name",ProcessText(data,"SubjectUserName",512));
            Put("process_user_domain",ProcessText(data,"SubjectDomainName",512));Put("process_logon_id",ProcessText(data,"SubjectLogonId",128));
            if(name is not null)roles["target_entity"]=name;return "scheduled_task."+change+".fragment";
        }
        if(id==4719){
            Put("audit_category_id",Text(data,"CategoryId"));Put("audit_subcategory_id",Text(data,"SubcategoryId"));
            Put("audit_subcategory_guid",Text(data,"SubcategoryGuid"));Put("audit_policy_changes",Text(data,"AuditPolicyChanges"));Put("subject_logon_id",Text(data,"SubjectLogonId"));
            var observed=new JsonObject{["state"]="observed",["kind"]="audit_policy_changed"};
            void Field(string key,params string[] names){string? v=Limited(data,512,names);if(v is not null)observed[key]=v;}
            Field("category_id","CategoryId","audit_category_id");Field("subcategory_id","SubcategoryId","audit_subcategory_id");
            Field("subcategory_guid","SubcategoryGuid","audit_subcategory_guid");Field("observed_value","AuditPolicyChanges","audit_policy_changes");
            if(observed.Count==2){observed["state"]="partial";observed["detail"]=new JsonObject{["state"]="unknown",["reason"]="audit_policy_fields_not_present"};}
            facts["observed_change"]=observed;return "audit.policy.changed";
        }
        bool added=id==4732;facts["change"]=added?"added":"removed";facts["group_scope"]="local";
        string? group=Text(data,"TargetSid","TargetUserName","GroupName"),member=Text(data,"MemberSid","MemberName");
        Put("group",group);Put("member",member);if(group is not null)roles["container_entity"]=group;if(member is not null)roles["target_entity"]=member;
        facts["group_sid"]=Limited(data,512,"TargetSid");facts["member_sid"]=Limited(data,512,"MemberSid");facts["member_name"]=Limited(data,512,"MemberName");
        facts["actor_sid"]=Limited(data,512,"SubjectUserSid");facts["actor_name"]=Limited(data,512,"SubjectUserName");facts["actor_domain"]=Limited(data,512,"SubjectDomainName");
        string? groupSid=Text(data,"TargetSid"),memberSid=Text(data,"MemberSid");
        bool exactGroup=groupSid is not null&&IsMatch(groupSid,@"(?i)^[sſ]-1-5-21-\d+-\d+-\d+-\d+$"),exactMember=memberSid is not null&&IsMatch(memberSid,@"(?i)^[sſ]-1-5-21-\d+-\d+-\d+-\d+$");
        quality["relation_membership_identity"]=new JsonObject{["state"]=exactGroup&&exactMember?"exact":"not_exact",["member_sid_field"]="MemberSid",["group_sid_field"]="TargetSid"};
        if(exactGroup&&exactMember){facts["relation_member_sid"]=memberSid!.ToUpperInvariant();facts["relation_group_sid"]=groupSid!.ToUpperInvariant();}
        return added?"group.member.added":"group.member.removed";
    }
}
