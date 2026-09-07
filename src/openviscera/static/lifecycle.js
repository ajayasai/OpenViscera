"use strict";
// Documentary workflow only: no erasure, physical automation, or implied legal authorization.
window.ovDisposed=sp=>Boolean(sp.disposed_at||S.current?.lifecycle?.specimens.find(x=>x.specimen_id===sp.id)?.disposed);
const lifeField=sp=>field("specimen_id","Specimen","select",{options:[[sp.id,sp.container_id]]});
const lifeReason=()=>field("reason","Decision rationale","textarea");
const lifeReference=()=>field("authority_reference","Policy or authority reference");
const lifeRecords=name=>S.current.case.controls?.[name]||[];
function lifeDecision(action,idField,id,title){commandForm(action,title,[
 field(idField,"Proposal","select",{options:[[id,id.slice(0,12)]]}),
 field("decision","Decision","select",{options:[["approve","Approve"],["reject","Reject"]]}),lifeReason()
],"Review the original instruction, authority and current case. Another account must make this decision. Rejected proposals remain in history.");}
function retentionForm(sp){commandForm("propose_retention","Propose retention instruction",[
 lifeField(sp),field("retain_until","Retain until (your local timezone)","datetime-local"),lifeReference(),lifeReason()
],"Enter the instruction approved by your organization or competent authority. There is no default legal retention period. A separate reviewer must approve every new or changed deadline; a pending change blocks disposal.");}
function holdForm(sp=null){commandForm("place_hold","Place preservation hold",[
 field("specimen_id","Hold scope","select",{options:sp?[[sp.id,sp.container_id]]:specimens(),optional:!sp}),lifeReference(),lifeReason()
],"Not selected means the entire case, including specimens collected later. A hold blocks disposal immediately, not laboratory work or opinion issue. Release needs a separate request and independent reviewer. A hold cannot recover already disposed material.");}
function releaseForm(hold){commandForm("request_hold_release","Request preservation hold release",[
 field("hold_id","Active hold","select",{options:[[hold.id,hold.authority_reference]]}),lifeReference(),lifeReason()
],"The hold stays active until another reviewer approves release. Recording a request does not authorize disposal.");}
function disposalForm(sp){commandForm("propose_disposal","Propose specimen disposal",[
 lifeField(sp),lifeReference(),field("method","Authorized disposal method (human-entered)"),lifeReason()
],"This records a proposal, not destruction. The approved retention deadline must have elapsed, all case work must be current, custody reconciled and all holds released. Only the local recorded custodian may propose. An independent reviewer must approve.");}
function certificateForm(sp){form("Attach disposal certificate",[
 lifeField(sp),field("file","Original administrative certificate","file",{accept:".pdf,.png,.jpg,.jpeg,.txt"})
],(data,key)=>uploadFile(data.file,data.specimen_id,key,"administrative"),
"Administrative certificates stay in the signed evidence bundle but do not change the clinical opinion fingerprint. They cannot be registered as laboratory reports. Do not classify clinical evidence as an administrative certificate.");}
function executeForm(proposal,sp){commandForm("record_disposal","Record completed disposal",[
 field("disposal_id","Approved proposal","select",{options:[[proposal.id,sp.container_id]]}),
 field("attachment_id","Matching administrative certificate","select",{options:S.current.case.attachments.filter(a=>a.specimen_id===sp.id&&a.purpose==="administrative").map(a=>[a.id,a.filename])}),
 field("occurred_at","Actual disposal time (after approval)","datetime-local"),field("note","Execution and certificate note","textarea")
],"Record only a disposal that actually occurred under separately verified authority. All gates and approval freshness are checked again. This permanently closes the physical workflow; it never deletes reports, opinions, attachments or history. No physical equipment is operated.");}
function reassignForm(){const s=S.current.case,p=s.controls?.access;
 commandForm("propose_reassignment","Propose examiner reassignment",[
 field("new_examiner_id","Replacement examiner","select",{options:options(S.catalog.users.filter(u=>u.active&&u.role==="examiner"&&u.id!==s.examiner_id&&(p?.mode!=="restricted"||p.member_ids.includes(u.id))),"display_name")}),lifeReason()
 ],"The replacement needs explicit access to a restricted case before proposal and approval. An independent reviewer must approve. Issued opinions are preserved; assignment change makes the current opinion fingerprint stale, requiring a new human-authored supplementary opinion. Pending reassignment blocks opinion approval and issue.");}
window.ovLifecycleBody=()=>{
 const s=S.current.case,life=S.current.lifecycle,root=h("div"),actions=h("div",{class:"actions"});
 if(allowed("admin","coordinator")||allowed("examiner")&&s.examiner_id===S.user.id)actions.append(button("Reassign examiner",reassignForm));
 if(allowed("examiner","coordinator","reviewer"))actions.append(button("Place case hold",()=>holdForm()));
 root.append(h("div",{class:"notice"},h("strong",{},"Preserve first. Review independently. "),"Retention dates and authority are human-entered. Expiry never triggers automatic disposal. This screen does not determine legal authority or scientific suitability."),actions);
 for(const entry of life.specimens){
  const sp=s.specimens.find(x=>x.id===entry.specimen_id),buttons=h("div",{class:"actions"});
  if(!entry.disposed){
   if(allowed("coordinator")||allowed("examiner")&&s.examiner_id===S.user.id)buttons.append(button("Set retention",()=>retentionForm(sp)));
   if(allowed("examiner","coordinator","reviewer"))buttons.append(button("Place specimen hold",()=>holdForm(sp)));
   if(allowed("examiner","coordinator")&&entry.eligible_for_proposal)buttons.append(button("Propose disposal",()=>disposalForm(sp)));
   if(entry.proposal&&allowed("examiner","coordinator","reviewer"))buttons.append(button("Cancel disposal proposal",()=>commandForm("cancel_disposal","Cancel disposal proposal",[field("disposal_id","Proposal","select",{options:[[entry.proposal.id,sp.container_id]]}),lifeReason()],"Cancellation is permanent and never erases the proposal or its approval.")));
   if(entry.proposal?.status==="pending"&&allowed("reviewer")&&entry.proposal.proposed_by!==S.user.id)buttons.append(button("Review disposal",()=>lifeDecision("decide_disposal","disposal_id",entry.proposal.id,"Review disposal proposal")));
   if(entry.proposal?.status==="approved"&&allowed("examiner","coordinator")&&sp.holder_id===S.user.id){
    buttons.append(button("Attach disposal certificate",()=>certificateForm(sp)));
    if(entry.eligible_to_record)buttons.append(button("Record completed disposal",()=>executeForm(entry.proposal,sp)));
   }
  }
  const body=h("div",{},h("p",{},"Recorded custodian: ",userName(sp.holder_id)," · Location: ",sp.location),
   h("p",{},entry.retention?`Retain until ${date(entry.retention.retain_until)} · ${entry.retention.authority_reference}`:"No independently approved retention instruction"),
   h("p",{},entry.disposed?pill("Disposed — physical workflow closed","bad"):entry.holds.length?pill(`${entry.holds.length} active preservation hold(s)`,"warn"):pill("No active preservation hold")),
   entry.proposal?h("p",{},`Disposal proposal: ${entry.proposal.status}`,entry.proposal_stale?pill("Stale — cancel and propose again","bad"):null):null,
   entry.disposed?h("p",{},`Disposal occurred ${date(entry.disposed.executed_at)}; original records remain retained.`):
    entry.blockers.length?h("details",{},h("summary",{},`${entry.blockers.length} disposal blocker(s)`),entry.blockers.map(text=>h("p",{},text))):h("p",{},"Recorded gates satisfied. Separate disposal authority still needs human verification."),buttons);
  root.append(panel(sp.container_id,body));
 }
 for(const [name,title,action,idField,label] of [
  ["reassignments","Examiner reassignment history","decide_reassignment","reassignment_id","Review reassignment"],
  ["retentions","Retention instruction history","decide_retention","retention_id","Review retention"],
  ["hold_releases","Hold release history","decide_hold_release","release_id","Review hold release"]]){
  const rows=lifeRecords(name).map(r=>[r.new_examiner_id?userName(r.new_examiner_id):r.authority_reference||r.hold_id,
   r.retain_until?date(r.retain_until):r.reason,userName(r.proposed_by),pill(r.status),
   allowed("reviewer")&&r.status==="pending"&&r.proposed_by!==S.user.id?button(label,()=>lifeDecision(action,idField,r.id,label)):r.decision_reason||"—"]);
  if(rows.length)root.append(panel(title,table(["Instruction / target","Deadline / rationale","Proposed by","Status","Decision"],rows)));
 }
 const holds=lifeRecords("holds");if(holds.length)root.append(panel("Preservation hold history",table(["Scope","Authority / reason","Status","Action"],holds.map(r=>[
  r.specimen_id?s.specimens.find(sp=>sp.id===r.specimen_id)?.container_id:"Entire case",h("div",{},r.authority_reference,h("p",{},r.reason)),pill(r.status),
  r.status==="active"&&allowed("examiner","coordinator","reviewer")&&!life.pending_hold_releases.some(x=>x.hold_id===r.id)?button("Request hold release",()=>releaseForm(r)):"—"
 ]))));
 const disposals=lifeRecords("disposals");if(disposals.length)root.append(panel("Disposal history",table(["Container","Authority / method","Status","Decision / completion"],disposals.map(r=>[
  s.specimens.find(sp=>sp.id===r.specimen_id)?.container_id,h("div",{},r.authority_reference,h("p",{},r.method)),pill(r.status),
  r.executed_at?`${date(r.executed_at)} · ${userName(r.executed_by)}`:r.cancellation_reason||r.decision_reason||"Awaiting independent decision"
 ]))));
 return root;
};
