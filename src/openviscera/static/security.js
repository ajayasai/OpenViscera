"use strict";
// Secrets exist only in the active form. Never localStorage, URLs, analytics or external QR services.
window.ovClearPrivateState=()=>{S.catalog={users:[],labs:[]};S.dashboard=null;S.current=null;S.security=null;S.search="";S.offset=0;};
window.ovCompleteLogin=async result=>{
 window.ovClearPrivateState();S.user=result.user;S.csrf=result.csrf;S.security=result.security||{};
 if(!S.security.enrollment_required&&!S.security.password_change_required)S.catalog=await api("/api/catalog");
 await route();
};
window.ovMfaLogin=challenge=>{
 const error=h("div",{class:"error",role:"alert"});
 const input=h("input",{id:"login-factor",name:"code",autocomplete:"one-time-code",required:true,maxlength:64});
 const submit=h("button",{type:"submit",class:"primary"},"Verify and sign in");
 const f=h("form",{class:"loginform"},h("div",{class:"eyebrow"},"SECOND FACTOR REQUIRED"),h("h2",{},"Verify your sign-in"),
 h("p",{class:"muted"},"Enter the six-digit code from your authenticator, or one unused recovery code. This challenge expires after five minutes."),
 h("div",{class:"field"},h("label",{for:"login-factor"},"Authentication or recovery code"),input),error,submit,
 button("Back to password sign-in",()=>{S.user=null;S.csrf=null;loginView();}));
 f.addEventListener("submit",async event=>{event.preventDefault();submit.disabled=true;error.textContent="";
  try{const result=await api("/api/login/mfa",{method:"POST",data:{challenge:challenge.challenge,code:input.value.trim()}});
   input.value="";await window.ovCompleteLogin(result);
  }catch(e){error.textContent=e.message;}finally{submit.disabled=false;}
 });
 $("#app").replaceChildren(h("main",{class:"security-login"},f));input.focus();
};
window.ovAccount=()=>navigate("security");
const securityProofFields=(mfa=true)=>[field("current_password","Current password","password"),
 ...(mfa?[field("code","Fresh authenticator or unused recovery code","text",{hint:"A code accepted at sign-in cannot be reused. Wait for the next code or use another recovery code."})]:[])];
function securityForm(title,fields,submit,help="",submitLabel="Confirm"){
 const modal=$("#modal");modal.replaceChildren();
 const f=h("form",{},h("div",{class:"modalhead"},h("h2",{id:"modal-title"},title),button("Close",()=>modal.close()))),
 error=h("div",{class:"error",role:"alert"}),save=h("button",{type:"submit",class:"primary"},submitLabel),controls={};
 if(help)f.append(h("p",{class:"muted"},help));
 for(const def of fields){const input=h("input",{id:"security-"+def.name,name:def.name,type:def.type||"text",required:true,
  autocomplete:def.type==="password"?(def.name==="new_password"?"new-password":"current-password"):"one-time-code",maxlength:def.type==="password"?1024:64});
  controls[def.name]=input;f.append(h("div",{class:"field"},h("label",{for:input.id},def.label),input,def.hint?h("small",{},def.hint):null));
 }
 f.append(error,h("div",{class:"modalactions"},button("Cancel",()=>modal.close()),save));
 f.addEventListener("submit",async event=>{event.preventDefault();save.disabled=true;error.textContent="";
  const values=Object.fromEntries(Object.entries(controls).map(([k,v])=>[k,v.value]));
  try{await submit(values);for(const input of Object.values(controls))input.value="";}
  catch(e){error.textContent=e.message;}finally{save.disabled=false;}
 });modal.append(f);modal.showModal();
}
function finishCredentialChange(){S.user=null;S.csrf=null;window.ovClearPrivateState();$("#modal").close();location.hash="security";loginView();}
function displayRecoveryCodes(codes){
 const modal=$("#modal");if(modal.open)modal.close();
 S.user=null;S.csrf=null;window.ovClearPrivateState();loginView();
 const box=h("pre",{class:"recovery-codes",tabindex:"0"},codes.join("\n"));
 const check=h("input",{id:"recovery-saved",type:"checkbox"}),done=button("I saved my codes — sign in",()=>{
  box.textContent="";codes.length=0;modal.close();modal.replaceChildren();loginView();},"primary",true);
 check.addEventListener("change",()=>{done.disabled=!check.checked;});
 modal.replaceChildren(h("section",{},h("div",{class:"modalhead"},h("h2",{id:"modal-title"},"Save your recovery codes")),
 h("p",{},"Shown once. Each code works once and still requires your password. Store them outside this browser, separately from your authenticator."),box,
 h("p",{class:"notice"},"All sessions were revoked. The enrollment code has already been used; wait for the next authenticator code or use one recovery code to sign in."),
 h("label",{for:"recovery-saved"},check," I have saved these codes securely"),h("div",{class:"modalactions"},done)));
 modal.dataset.recovery="1";modal.showModal();
}
function enrollAuthenticator(){
 securityForm("Set up an authenticator",securityProofFields(false),async data=>{
  const setup=await api("/api/account/mfa/setup",{method:"POST",data});
  const password=data.current_password;
  $("#modal").close();
  securityForm("Confirm your authenticator",[field("code","Current six-digit authenticator code")],async values=>{
   const result=await api("/api/account/mfa/confirm",{method:"POST",data:{current_password:password,code:values.code.trim()}});
   displayRecoveryCodes(result.recovery_codes);
  },"Scan this QR in an authenticator or enter the setup key manually. The setup expires in ten minutes. Treat the key and QR as a password.","Enable MFA");
  const qr=h("div",{class:"mfa-provisioning"},h("img",{src:setup.qr_data_url,alt:"Authenticator enrollment QR — contains a secret key",width:240,height:240}),
   h("p",{},"Manual setup key"),h("code",{class:"mono break",id:"mfa-setup-secret"},setup.secret),
   h("p",{class:"muted"},"Time-based · SHA-1 · 6 digits · 30 seconds. QR generated locally; no external service."));
  $("#modal").querySelector(".field").before(qr);
 },"Verify your password before creating a secret. Existing sessions are revoked once MFA is confirmed.","Create setup key");
}
window.ovSecurityView=async content=>{
 const state=await api("/api/account/security");S.security=state;
 content.append(pagehead("Account security","Protect sign-in, review active sessions, and manage recovery without a cloud dependency."));
 if(state.password_change_required)content.append(h("div",{class:"notice"},"Your account was recovered by a local operator. Set a personal password before accessing any case data."));
 else if(state.enrollment_required)content.append(h("div",{class:"notice"},"This deployment requires MFA. Complete authenticator enrollment before accessing case records, queues, exports or administration."));
 const buttons=h("div",{class:"actions"});
 buttons.append(button("Change password",()=>securityForm("Change your password",[
  ...securityProofFields(state.mfa_enabled),field("new_password","New password (14+ characters)","password")],async data=>{
   await api("/api/account/password",{method:"POST",data});finishCredentialChange();
  },"Current password and, when enabled, a fresh second factor are required. This revokes every session and pending sign-in challenge.","Change password and sign out")));
 if(!state.password_change_required){
  if(!state.mfa_enabled)buttons.append(button("Set up authenticator",enrollAuthenticator,"primary"));
  else{
   buttons.append(button("Regenerate recovery codes",()=>securityForm("Regenerate recovery codes",securityProofFields(),async data=>{
    const result=await api("/api/account/mfa/recovery-codes",{method:"POST",data});displayRecoveryCodes(result.recovery_codes);
   },"This invalidates all old recovery codes and every session. Save the replacement codes before signing in again.")));
   if(!state.mfa_required_by_policy)buttons.append(button("Disable MFA",()=>securityForm("Disable multi-factor authentication",securityProofFields(),async data=>{
    await api("/api/account/mfa/disable",{method:"POST",data});finishCredentialChange();
   },"Your password and one fresh factor are required. Every session is revoked; future sign-ins will use password only."),"danger"));
  }
 }
 content.append(panel("Sign-in protection",h("div",{},h("p",{},pill(state.mfa_enabled?"MFA enabled":"Password only",state.mfa_enabled?"good":"warn")),
  h("p",{},state.mfa_enabled?`${state.recovery_codes_remaining} unused recovery codes remain.`:"An authenticator adds a second factor to your password."),
  h("p",{class:"muted"},"Authenticator codes are not phishing-resistant passkeys. Never give a code to someone claiming to provide support."),buttons)));
 const when=value=>date(new Date(value*1000).toISOString());
 const revoke=async id=>{const result=await api("/api/account/sessions/revoke",{method:"POST",data:{session_id:id}});
  if(result.reauthentication_required)finishCredentialChange();else await route();};
 content.append(panel("Active sessions",table(["Signed in","Expires","Authentication","Session","Action"],state.sessions.map(s=>[
  when(s.created_at),when(s.expires_at),s.method,s.current?pill("This browser","good"):s.id.slice(0,12),
  state.password_change_required?"Password change required":button(s.current?"Sign out this session":"Revoke session",()=>revoke(s.id))
 ])),!state.password_change_required?button("Revoke all other sessions",async()=>{await api("/api/account/sessions/revoke",{method:"POST",data:{others:true}});await route();}):null));
 content.append(h("p",{class:"muted"},"Lost both your authenticator and recovery codes? Contact your deployment operator for documented, identity-verified local recovery. Web administrators cannot silently remove another user's MFA."));
};
$("#modal").addEventListener("close",()=>{if(!$("#modal").open){$("#modal").replaceChildren();delete $("#modal").dataset.recovery;}});
$("#modal").addEventListener("cancel",event=>{if($("#modal").dataset.recovery)event.preventDefault();});
