"use strict";
// v0.2 operator controls. All permissions and transitions are checked again server-side.
window.ovAccount=()=>form("Change your password",[
 field("current_password","Current password","password"),field("new_password","New password (14+ characters)","password")
],async(data)=>{await api("/api/account/password",{method:"POST",data});S.user=null;S.csrf=null;},
"Your current password is required. Every existing session will be revoked; sign in again with the new password.","Change password and sign out");

window.ovLocate=()=>form("Find specimen by label or scanner",[field("token","Container identifier or QR payload")],async(data)=>{
 const found=await api("/api/locate?token="+encodeURIComponent(data.token));S.tab="specimens";location.hash="case/"+found.case_id;
},"Enter a container identifier or scan the opaque OpenViscera QR payload with a keyboard-input scanner. Restricted cases remain protected.","Find specimen");

window.ovBatch=()=>{
 const original=S.current.case;
 const eligible=original.specimens.filter(sp=>sp.holder_id===S.user.id&&!sp.quarantined&&sp.seal_ref&&!original.transfers.some(t=>t.specimen_id===sp.id&&!t.acknowledged_at));
 const recipients=S.catalog.users.filter(u=>u.active&&u.id!==S.user.id&&["examiner","coordinator","courier","lab"].includes(u.role));
 let previewed=null;
 const transform=data=>({expected_version:original.version,items:data.specimen_ids.map(id=>({specimen_id:id,recipient_id:data.recipient_id,occurred_at:data.occurred_at,destination:data.destination,note:data.note}))});
 const fields=[field("specimen_ids","Sealed containers to hand over","multiselect",{options:eligible.map(sp=>[sp.id,sp.container_id]),value:eligible.map(sp=>sp.id)}),
 field("recipient_id","Named receiving account","select",{options:options(recipients,"display_name")}),field("destination","Destination"),
 field("occurred_at","Handover time","datetime-local",{value:localTime()}),field("note","Handover note","textarea")];
 form("Preview and commit a dispatch batch",fields,async(data,key)=>{
  const payload=transform(data);if(JSON.stringify(payload)!==previewed)throw new Error("Preview the current selections before committing.");
  const result=await api(`/api/cases/${original.id}/batch-handover`,{method:"POST",data:payload,key});S.current.case=result.case;
 },"A batch is all-or-nothing. Each container gets its own signed handover event and still needs the named recipient's acknowledgement.","Commit entire batch");
 const modal=$("#modal"),save=modal.querySelector("button[type=submit]"),result=h("p",{class:"notice",role:"status"},"Preview is required. No custody record has been created.");
 save.disabled=true;
 modal.querySelector(".modalactions").before(result);
 modal.querySelector("form").addEventListener("input",()=>{previewed=null;save.disabled=true;result.textContent="Selections changed. Preview again before committing.";});
 const preview=button("Preview batch",async()=>{
  if(!modal.querySelector("form").reportValidity())return;
  preview.disabled=true;
  try{const get=name=>modal.querySelector(`[name=${name}]`);
   const data={specimen_ids:[...get("specimen_ids").selectedOptions].map(o=>o.value),recipient_id:get("recipient_id").value,
    destination:get("destination").value,occurred_at:new Date(get("occurred_at").value).toISOString(),note:get("note").value};
   const payload=transform(data);const checked=await api(`/api/cases/${original.id}/batch-handover`,{method:"POST",data:{...payload,preview:true},key:idkey()});
   previewed=JSON.stringify(payload);save.disabled=false;result.textContent=`Validated ${checked.count} containers against case version ${checked.expected_version}. Nothing has been dispatched yet.`;
  }catch(e){previewed=null;save.disabled=true;result.textContent=e.message;}finally{preview.disabled=false;}
 });modal.querySelector(".modalactions").prepend(preview);
};

function accessPolicyForm(){const s=S.current.case,p=s.controls?.access;
 form("Manage case access",[
  field("mode","Access scope","select",{options:[["department","Department"],["restricted","Restricted named members"]],value:p?.mode||"department"}),
  field("member_ids","Members for restricted access","multiselect",{options:options(S.catalog.users.filter(u=>u.active),"display_name"),value:p?.member_ids||[s.examiner_id,S.user.id].filter((v,i,a)=>a.indexOf(v)===i)}),
  field("reason","Access-change reason","textarea")],(data,key)=>command("access_policy",{...data,member_ids:data.mode==="department"?[]:data.member_ids},key),
 "Restricted records disappear from other users' register, queues, scanner lookup and downloads. Administrators do not automatically bypass this policy. Keep the assigned examiner, current manager, and necessary independent reviewer as members.");
}
function correctionForm(caseAuthority=false){const s=S.current.case;
 const fields=caseAuthority?[field("replacement","Correct requesting-authority text")]:[
  field("target_id","Specimen","select",{options:specimens()}),field("field","Field to correct","select",{options:["description","preservative","quantity","unit"].map(x=>[x,x])}),field("replacement","Corrected recorded value")];
 fields.push(field("reason","Correction rationale","textarea"));
 form(caseAuthority?"Propose requesting-authority correction":"Propose specimen correction",fields,(data,key)=>{
  const target=caseAuthority?s:s.specimens.find(sp=>sp.id===data.target_id);const property=caseAuthority?"authority":data.field;
  return command("correct",{target:caseAuthority?"case":"specimen",target_id:target.id,field:property,expected_value:String(target[property]),replacement:data.replacement,reason:data.reason},key);
 },"Nothing is overwritten on proposal. Another reviewer must approve or reject it. The original value, correction reason and both identities remain in the signed history. Container identity, custody and timestamps cannot be changed here.");
}
function controlDecision(action,record,idField,title){form(title,[field("decision","Decision","select",{options:[["approve","Approve"],["reject","Reject"]]}),field("reason","Independent review rationale","textarea")],
 (data,key)=>command(action,{...data,[idField]:record.id},key),"Review the original evidence and proposal. You cannot decide your own proposal; this decision is permanent.");}
function withdrawalForm(opinion=false){const s=S.current.case;const values=opinion?s.opinions.filter(o=>o.issued_at&&S.current.opinion_status[o.id]!=="withdrawn").map(o=>[o.id,o.kind+" · "+date(o.issued_at)]):s.reports.filter(r=>!["withdrawn","disputed"].includes(S.current.report_status[r.id])).map(r=>[r.id,r.laboratory_reference+" · revision "+r.revision]);
 commandForm(opinion?"withdraw_opinion":"withdraw_report",opinion?"Withdraw an issued opinion":"Propose laboratory-report withdrawal",[
 field(opinion?"opinion_id":"report_id",opinion?"Issued opinion":"Laboratory report","select",{options:values}),field("reason","Withdrawal reason","textarea")],
 opinion?"This immediately marks the issued opinion as withdrawn without deleting its text. A new supplementary opinion needs independent approval and issue. This does not recall copies already delivered outside the application.":
 "The report becomes disputed immediately and cannot satisfy opinion readiness. Another reviewer must approve or reject the withdrawal. No older report version is silently reinstated.");
}
window.ovRequestReceipt=(request=null)=>{const s=S.current.case;const pending=s.requests.filter(r=>!r.received_at&&(!request||r.id===request.id));
 const fields=[field("request_id","Additional examination request","select",{options:pending.map(r=>[r.id,r.examination+" · "+labName(r.lab_id)])}),
 field("accepted_at","Laboratory accepted request at","datetime-local",{value:localTime(0),hint:"Must follow the creation of this additional request. This is not a new physical handover."}),
 field("attachment_id","Acceptance evidence","select",{options:s.attachments.map(a=>[a.id,a.filename]),optional:allowed("lab")}),field("note","Laboratory confirmation note","textarea")];
 // Leave confirmation time blank: the operator must enter the actual acceptance time.
 fields.find(f=>f.name==="accepted_at").value="";
 commandForm("request_receipt","Confirm an additional laboratory request",fields,
 "Use this for a new examination of a specimen already at the laboratory. Staff transcription requires a matching receipt attachment; an authenticated laboratory account may confirm its own request directly.");
};
function returnForm(){const s=S.current.case;commandForm("record_return","Record a documented external return",[
 field("specimen_id","Externally held specimen","select",{options:s.specimens.filter(sp=>sp.holder_id.startsWith("external:")).map(sp=>[sp.id,sp.container_id])}),
 field("attachment_id","Return receipt evidence","select",{options:s.attachments.map(a=>[a.id,a.filename])}),field("external_sender_name","Named external sender"),
 field("occurred_at","Returned to you at","datetime-local",{value:localTime()}),field("observed_seal","Seal actually observed"),field("discrepancy","Additional discrepancy","checkbox"),
 field("destination","Department receiving location"),field("note","Return and condition note","textarea")],
 "You are recording receipt as the receiving custodian. The external sender is documented, not authenticated. Mismatched seals automatically open a discrepancy; an existing discrepancy is never cleared by return.");}
window.ovControlsBody=()=>{const s=S.current.case,controls=s.controls||{},content=h("div");
 const acl=controls.access;content.append(h("div",{class:"notice"},h("strong",{},acl?.mode==="restricted"?"Restricted named-member case. ":"Department-access case. "),
 acl?.mode==="restricted"?`${acl.member_ids.length} explicitly listed accounts. All normal role restrictions still apply.`:"All department staff have their normal role-based access. No external publication is enabled."));
 const actions=h("div",{class:"actions"});
 if(allowed("admin")||allowed("examiner")&&s.examiner_id===S.user.id)actions.append(button("Manage case access",accessPolicyForm));
 if(allowed("coordinator")||allowed("examiner")&&s.examiner_id===S.user.id)actions.append(button("Correct specimen",()=>correctionForm()),button("Correct authority",()=>correctionForm(true)),button("Withdraw report",()=>withdrawalForm()));
 if(allowed("reviewer")||allowed("examiner")&&s.examiner_id===S.user.id)actions.append(button("Withdraw issued opinion",()=>withdrawalForm(true),"danger"));
 if(allowed("examiner","coordinator"))actions.append(button("Record external return",returnForm));
 if(allowed("examiner","coordinator","lab"))actions.append(button("Confirm additional request",()=>window.ovRequestReceipt()));
 content.append(actions,h("p",{class:"muted"},"All proposals, decisions and withdrawals remain in the signed case chronology. Pending corrections and disputed reports block opinion approval and issue."));
 const corrections=controls.corrections||[];
 content.append(h("h3",{},"Controlled corrections"),corrections.length?table(["Target / field","Before → proposed","Status","Decision"],corrections.map(c=>[
  c.target+" / "+c.field,h("div",{},c.expected_value,h("div",{},"→ "+c.replacement),h("small",{class:"muted"},c.reason)),pill(c.status,c.status==="pending"?"warn":""),
  c.status==="pending"&&allowed("reviewer")?button("Review correction",()=>controlDecision("decide_correction",c,"correction_id","Decide proposed correction")):c.decision_reason||"Independent decision pending"
 ])):h("p",{class:"muted"},"No correction proposals."));
 content.append(h("h3",{},"Report withdrawal decisions"),(controls.report_withdrawals||[]).length?table(["Report","Reason","Status","Decision"],controls.report_withdrawals.map(w=>[
  s.reports.find(r=>r.id===w.report_id)?.laboratory_reference||w.report_id,w.reason,pill(w.status,w.status==="approved"?"bad":w.status==="pending"?"warn":""),
  w.status==="pending"&&allowed("reviewer")?button("Review withdrawal",()=>controlDecision("decide_withdrawal",w,"withdrawal_id","Decide report withdrawal")):w.decision_reason||"Independent decision pending"
 ])):h("p",{class:"muted"},"No report withdrawals."));
 content.append(h("h3",{},"Opinion withdrawals"),(controls.opinion_withdrawals||[]).length?table(["Opinion","Withdrawn by","Reason","Recorded"],controls.opinion_withdrawals.map(w=>[
  w.opinion_id.slice(0,12),userName(w.withdrawn_by),w.reason,date(w.withdrawn_at)
 ])):h("p",{class:"muted"},"No issued opinions withdrawn."));return content;
};
window.ovAuditView=async(content)=>{
 const offset=S.auditOffset||0,page=await api(`/api/admin/access-audit?offset=${offset}&limit=50`);
 content.append(pagehead("Access audit","Signed department-level request metadata. No passwords, request bodies or case narratives are logged."));
 const rows=page.events.map(e=>[String(e.body.seq),date(e.body.recorded_at),userName(e.body.actor_id),e.body.method+" "+e.body.route,
  pill(String(e.body.status),e.body.status>=400?"warn":"good"),h("span",{class:"mono break"},e.body.case_ids.map(id=>id.slice(0,12)).join(", ")||"—")]);
 const auditTable=table(["Sequence","Recorded","Account","Operation","Status","Opaque case IDs"],rows);auditTable.classList.add("audit-table");
 content.append(panel("Verified access records",auditTable),
 h("p",{class:"mono break"},"Verified department chain head: "+page.head),
 h("p",{class:"muted"},"This audit view itself creates a subsequent access event. Audit metadata is available to department administrators and auditors even when clinical case contents are restricted."),
 h("div",{class:"pager"},`${page.total} records at snapshot`,button("Previous",()=>{S.auditOffset=Math.max(0,offset-50);route();},"",offset===0),button("Next",()=>{S.auditOffset=offset+50;route();},"",offset+50>=page.total)));
};
