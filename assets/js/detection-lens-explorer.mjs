// Load the same versioned evidence projection served by the report. Rendering
// selects recorded results for the current controls without changing verdicts.
async function initialize(root) {
  const response = await fetch(root.dataset.dataset);
  if (!response.ok) throw new Error("Study request failed");
  const model = await response.json();
  if (model.schema !== "detection-lens-explorer/v1" || !Array.isArray(model.studies)) {
    throw new Error("Unsupported study dataset");
  }
  const $ = id => root.querySelector("#" + id);
  const states = {C:"Confirmed", O:"Observed", L:"Coverage limited", N:"No match", T:"Attempt only", "-":"Not adjudicated"};
  const claimNames = {capture:"Native capture", operation:"Operation observed", effect:"Downstream effect",
    attribution:"Exact attribution", authorization:"Authorization violation", boundary:"Boundary-policy violation",
    causal:"Causal relationship", objective:"Adversary objective"};
  const probeNotes = {
    "gate-b":"Synthetic controls make object, operation and policy linkage explicit.",
    "gate-c":"The helper result is measurable even when the direct return is missing.",
    "gate-c2":"Choose an earlier cutoff to separate a visible downstream effect from a missing upstream link.",
    "gate-c3":"The complementary observer is modeled. There are no live C.3 results.",
    "windows":"The process comparison uses separately documented cohorts.",
    "php":"An authorized read can produce the same resource outcome.",
  };
  const choices = {
    delay:{study:"gate-c3",case:"R01",profile:"augmented",cutoff:1000,arm:"B",selected:"causal"},
    gap:{study:"gate-c2",case:"C2-03",profile:"augmented",cutoff:null,selected:"operation"},
    arms:{study:"gate-c3",case:"R01",profile:"augmented",cutoff:null,arm:"A",selected:"effect"},
  };
  function node(tag, cls, text){
    const a=document.createElement(tag);
    if(cls) a.className=cls;
    if(text!==undefined) a.textContent=text;
    return a;
  }
  function reset(id){
    const study=model.studies.find(s=>s.id===id);
    const g=study.groups.at(-1);
    return {study:id,case:study.initialCase,profile:g.profile,cutoff:g.cutoff,arm:g.arm,
            lenses:study.lenses,cohort:Object.keys(study.cohorts)[0],claim:"effect",selected:"effect",objectiveFilter:"all"};
  }
  const unique = items => [...new Set(items)];
  const order = (study, letters) => [...study.lenses].filter(x=>letters.includes(x)).join("");
  function view(state){
    const study=model.studies.find(s=>s.id===state.study);
    const g=study.groups.find(row=>row.profile===state.profile&&row.cutoff===state.cutoff&&row.arm===state.arm);
    const row=g.rows[state.lenses];
    const metrics=row[0][state.cohort]||{};
    return {study,g,row,metrics,assessment:study.assessments[row[1][state.case]],
            example:study.cases[state.case]};
  }
  function change(old, patch){
    const fresh=patch.study&&patch.study!==old.study? reset(patch.study):old;
    const next={...fresh,...patch};
    const study=model.studies.find(s=>s.id===next.study);
    if(next.objectiveFilter!=="all"&&study.cases[next.case].objective!==next.objectiveFilter)
      next.case=Object.keys(study.cases).find(key=>study.cases[key].objective===next.objectiveFilter);
    if(study.mode==="comparison"&&next.case!==fresh.case)
      next.cohort=study.cases[next.case].cohort;
    next.lenses=order(study,next.lenses);
    if(!study.groups.some(g=>g.profile===next.profile&&g.cutoff===next.cutoff&&g.arm===next.arm)){
      const fallback=study.groups.find(g=>g.profile===next.profile&&g.arm===next.arm)||study.groups.at(-1);
      Object.assign(next,{profile:fallback.profile,cutoff:fallback.cutoff,arm:fallback.arm});
    }
    return next;
  }
  function selection(el, values, chosen){
    const fragment=document.createDocumentFragment();
    values.forEach(([value,label])=>{
      const item=node("option","",label);
      item.value=String(value);
      item.selected=String(value)===String(chosen);
      fragment.append(item);
    });
    if (Array.from(el.options).map(o=>o.value+"\0"+o.text).join("\u0001")!==values.map(([id,label])=>String(id)+"\0"+label).join("\u0001")) el.replaceChildren(fragment);
    el.value=String(chosen);
    el.disabled=values.length<2;
  }
  function claimValue(assessment,id){
    const ix=model.claims.indexOf(id);
    return assessment?.[ix]||["-",[],[]];
  }
  function claimLabel(study, id, cohort=state.cohort){
    if (id==="effect"&&study.cohortEffectLabels?.[cohort]) return study.cohortEffectLabels[cohort];
    if (id==="effect" && study.id==="windows") return "Child process creation";
    if (id==="effect" && study.id==="php") return "Designated file-read confirmation";
    if (id==="effect" && ["gate-b","gate-c"].includes(study.id)) return "Policy-violating effect";
    return claimNames[id]||id;
  }
  let state=reset("gate-c2");
  function set(patch){state=change(state,patch);render();}

  const lessons = [
    {id:"convergence", label:"Same objective", question:"Can different execution paths produce the same confirmed effect?",
     context:"The PHP study holds the target file constant. Compare a child read, an in-process read, and the approved twin.",
     steps:[
       {name:"Inspect the child read", point:{study:"php",case:"child",selected:"effect"}},
       {name:"Switch to in-process", point:{study:"php",case:"worker",selected:"effect"}},
       {name:"Check the approved twin", point:{study:"php",case:"admin",selected:"authorization"}}
     ],
     result({study,example,assessment}) {
       if(study.id!=="php"||example.objective!=="file_read")return null;
       const outcome=claimValue(assessment,"effect")[0];
       const policy=claimValue(assessment,"authorization")[0];
       return [ "File effect "+states[outcome]+" · Policy "+states[policy],
         "Both tested execution paths reached the same designated file. The approved twin preserves the effect and changes the authorization finding. The test establishes a scoped read convergence." ];
     }},
    {id:"resilience", label:"Missing upstream", question:"What can be confirmed with the upstream evidence missing or late?",
     context:"Use the measured C.2 delegated case. Compare the early receipt window, the final view, and the same final view with the upstream evidence unavailable.",
     steps:[
       {name:"Look at 250 ms", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:250,selected:"causal"}},
       {name:"Allow later receipts", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,selected:"causal"}},
       {name:"Keep only effect evidence", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                   cohort:"path/workload_delegated",claim:"effect",selected:"causal"}, applyMinimum:"effect"}
     ],
     result({study,g,assessment}) {
       if(study.id!=="gate-c2"||state.case!=="C2-02")return null;
       return ["Downstream effect "+states[claimValue(assessment,"effect")[0]]+
         " · Boundary "+states[claimValue(assessment,"boundary")[0]]+
         " · Causal edge "+states[claimValue(assessment,"causal")[0]],
         g.cutoff!==null?"At an early cutoff, the completed downstream effect can have sufficient evidence while the causal record is still unavailable.":
           "The final replay can link the measured case with its full evidence. Keep only the effect lenses to see the node survive without a confirmed edge."];
     }},
    {id:"observation", label:"Behavior vs. sensor", question:"Does an unobserved operation establish that it did not happen?",
     context:"Compare separate reference and runtime runs of the same fixed write variants in C.2. Then inspect the synthetic recovery arm in C.3.",
     steps:[
       {name:"Inspect vectored writes", point:{study:"gate-c2",case:"C2-03",profile:"augmented",cutoff:null,selected:"operation"}, diagnostic:1},
       {name:"Compare the scalar control", point:{study:"gate-c2",case:"C2-03",profile:"augmented",cutoff:null,selected:"operation"}, diagnostic:2},
       {name:"Inspect the modeled sensor", point:{study:"gate-c3",case:"R01",profile:"augmented",cutoff:null,arm:"B",claim:"capture",selected:"capture"}}
     ],
     result({study,assessment,metrics}) {
       if(study.id==="gate-c3"&&state.case==="R01"){
         const count=metrics.capture;
         return ["Synthetic native capture "+states[claimValue(assessment,"capture")[0]]+(count?" · "+count[0]+" / "+count[1]+" eligible operations":""),
          "The complementary arm models an additional return observation. Runtime attachment and recovery are still unmeasured."];
       }
       if(study.id!=="gate-c2")return null;
       const d=study.diagnostic, i=lessons[2].steps[lessonStep].diagnostic??1;
       return [d.labels[i]+" · Reference "+d.reference[i]+" / "+d.denominator+
         " · Runtime hook "+d.observed[i]+" / "+d.denominator,
         "The behavior is the write. The observer is one collection point. The reference runs verified completion for the vectored variants, while the selected runtime hook missed them."];
     }},
    {id:"minimum", label:"Minimum evidence", question:"Which lenses are sufficient for the effect, and which are sufficient for the edge?",
     context:"Inspect the measured C.2 delegated cohort in retrospective replay. The target and negative controls belong to this study.",
     steps:[
       {name:"Load the effect minimum", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                 cohort:"path/workload_delegated",claim:"effect",selected:"effect"}, applyMinimum:"effect"},
       {name:"Test the same lenses for causality", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                            cohort:"path/workload_delegated",claim:"causal",selected:"causal"}, applyMinimum:"effect"},
       {name:"Load the causal minimum", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                 cohort:"path/workload_delegated",claim:"causal",selected:"causal"}, applyMinimum:"causal"}
     ],
     result({study,g,metrics}) {
       if(study.id!=="gate-c2"||state.cohort!=="path/workload_delegated")return null;
       const count=metrics[state.claim], recorded=g.minimum[state.cohort]?.[state.claim];
       if(!count)return null;
       return [shortMask(state.lenses)+" · "+count[0]+" / "+count[1]+" "+claimLabel(study,state.claim).toLowerCase()+
         " · Minimum "+(recorded?.length?recorded.map(shortMask).join(" or "):"none qualified"),
         state.claim==="causal"?"The edge needs more evidence than the effect. Select the recorded causal minimum or toggle lenses to observe the change.":
         "A minimum is specific to the cohort, claim, and receipt cutoff. The selected cohort’s effect minimum may leave authorization, attribution, or causal questions unanswered."];
     }},
  ];
  let activeLesson=null,lessonStep=0;
  function applyLessonStep(step){
    const lesson=lessons.find(item=>item.id===activeLesson);
    lessonStep=step;
    const data=lesson.steps[step];
    state=change(reset(data.point.study),data.point);
    const {g}=view(state);
    if(data.applyMinimum){
      const recorded=g.minimum[state.cohort]?.[data.applyMinimum];
      if(recorded?.length) state=change(state,{lenses:recorded[0]});
    }
    render();
  }
  function selectLesson(id){
    activeLesson=id;
    applyLessonStep(0);
  }
  function lessonTabs(){
    const tabs=$("lesson-tabs");
    for(const l of lessons){
      const tab=node("button","",l.label);
      tab.type="button"; tab.id="lesson-tab-"+l.id;
      tab.dataset.lesson=l.id;
      tab.setAttribute("role","tab");
      tab.setAttribute("aria-controls","lesson-panel");
      tab.addEventListener("click",()=>selectLesson(l.id));
      tabs.append(tab);
    }
    tabs.addEventListener("keydown",event=>{
      const keys=["ArrowRight","ArrowLeft","Home","End"];
      if(!keys.includes(event.key)||!event.target.matches('[role="tab"]'))return;
      event.preventDefault();
      const at=lessons.findIndex(item=>item.id===event.target.dataset.lesson);
      const last=lessons.length-1;
      const ix=event.key==="Home"?0:event.key==="End"?last:(at+(event.key==="ArrowRight"?1:-1)+lessons.length)%lessons.length;
      selectLesson(lessons[ix].id);
      $("lesson-tab-"+lessons[ix].id).focus();
    });
    $("free-explore").addEventListener("click",()=>{
      const previous=activeLesson;
      activeLesson=null;
      render();
      $("lesson-tab-"+previous).focus();
    });
  }
  function renderLesson(current){
    const panel=$("lesson-panel");
    const lesson=lessons.find(item=>item.id===activeLesson);
    for(const [ix,l] of lessons.entries()){
      const tab=$("lesson-tab-"+l.id);
      tab.setAttribute("aria-selected",String(l.id===activeLesson));
      tab.tabIndex=(activeLesson?l.id===activeLesson:ix===0)?0:-1;
    }
    panel.hidden=!lesson;$("free-explore").hidden=!lesson;
    if(!lesson)return;
    panel.setAttribute("aria-labelledby","lesson-tab-"+lesson.id);
    $("lesson-question").textContent=lesson.question;
    $("lesson-context").textContent=lesson.context;
    const container=$("lesson-steps");
    if(container.dataset.lesson!==lesson.id){
      container.dataset.lesson=lesson.id;
      container.replaceChildren(...lesson.steps.map((item,ix)=>{
        const b=node("button","",item.name);
        b.type="button";b.addEventListener("click",()=>applyLessonStep(ix));
        return b;
      }));
    }
    Array.from(container.children).forEach((b,i)=>b.setAttribute("aria-pressed",String(i===lessonStep)));
    const result=lesson.result(current)||["The explorer is showing other evidence.",
      "Use a lesson step to return to the study and settings used in this demonstration."];
    $("lesson-proof").textContent=result[0];
    $("lesson-conclusion").textContent=result[1];
  }
  function graphButton(role,title,key,assessment){
    const v=claimValue(assessment,key)[0];
    const b=node("button","node");
    b.type="button"; b.dataset.v=v;b.dataset.focus="graph-"+key;
    b.setAttribute("aria-pressed",String(state.selected===key));
    b.append(node("span","role",role),node("span","node-title",title));
    const marker=node("span","state",key==="path"?"Scenario context":states[v]);
    marker.dataset.v=v; b.append(marker);
    b.addEventListener("click",()=>set({selected:key}));
    return b;
  }
  function arrow(){const a=node("span","arrow","→");a.setAttribute("aria-hidden","true");return a;}
  function shortMask(mask){return mask?mask.split("").join(" · "):"Empty set";}
  function renderBowtie(study,example){
    const left=node("div","bowtie-stack"), right=node("div","bowtie-stack");
    const entries=Object.entries(study.cases);
    const peerPaths=new Map();
    for(const [key,value] of entries){
      if(value.objective===example.objective&&!peerPaths.has(value.path)) peerPaths.set(value.path,key);
    }
    for(const [path,key] of peerPaths){
      const b=node("button","",model.paths[path]||path);
      b.dataset.focus="bowtie-path-"+path;
      b.setAttribute("aria-pressed",String(path===example.path));
      b.addEventListener("click",()=>set({case:key,selected:"path"}));left.append(b);
    }
    const bridge=node("article","","Conditional boundary or shared interaction");
    const outcomes=new Map();
    for(const [key,value] of entries)
      if((state.objectiveFilter==="all"||value.objective===example.objective)&&!outcomes.has(value.objective)) outcomes.set(value.objective,key);
    for(const [objective,key] of outcomes){
      const b=node("button","",model.objectives[objective][1]);
      b.dataset.focus="bowtie-effect-"+objective;
      b.setAttribute("aria-pressed",String(objective===example.objective));
      b.addEventListener("click",()=>set({case:key,selected:"effect"}));right.append(b);
    }
    $("bowtie").replaceChildren(left,arrow(),bridge,arrow(),right);
  }
  function renderGraph(study,example,assessment){
    const graph=$("graph");graph.replaceChildren();
    const objective=model.objectives[example.objective];
    $("objective-name").textContent=objective[0];
    $("path-label").textContent=model.paths[example.path]||"Other path";
    renderBowtie(study,example);
    const upper=node("div","upstream");
    const upstreamSupported=["gate-c2","gate-c3"].includes(study.id);
    upper.append(graphButton("Scenario origin",model.paths[example.path]||"Observed actor","path",assessment),
      arrow(),
      graphButton(upstreamSupported?"Conditional upstream node":"Execution path",
      upstreamSupported?"Boundary-policy claim":example.path==="delegated"?"Helper handoff":"Request or worker",
      upstreamSupported?"boundary":"attribution",assessment));
    graph.append(upper);
    const es=node("div","edge-shell");
    const edge=claimValue(assessment,"causal")[0];
    const button=node("button","state","Causal edge · "+states[edge]);
    button.dataset.focus="graph-causal";
    es.dataset.v=edge;button.dataset.v=edge;button.setAttribute("aria-pressed",String(state.selected==="causal"));
    button.addEventListener("click",()=>set({selected:"causal"}));
    es.append(button);graph.append(es);
    const lower=node("div","downstream");
    lower.append(graphButton("Observation","Operation recorded","operation",assessment),arrow(),
      graphButton("Independent effect",objective[1],"effect",assessment),arrow(),
      graphButton("Policy", "Authorization verdict","authorization",assessment));
    graph.append(lower);
    const badges=node("div","badge-row");
    for(const key of ["attribution","capture","objective"]){
      const v=claimValue(assessment,key)[0];
      const b=node("button","state",claimNames[key]+" · "+states[v]);
      b.dataset.focus="graph-badge-"+key;
      b.dataset.v=v;b.setAttribute("aria-pressed",String(state.selected===key));
      b.addEventListener("click",()=>set({selected:key}));badges.append(b);
    }
    graph.append(badges);
    $("graph-note").textContent="Solid arrows describe the scenario. The labeled causal edge carries its own evidence verdict.";
    const displayed=study.caseNotes?.[state.case];
    const [status,refs,missing]=claimValue(assessment,state.selected);
    $("inspect-title").textContent=state.selected==="path"?"Scenario alternatives":claimLabel(study,state.selected,example.cohort);
    $("inspect-status").textContent=(state.selected==="path"?"Objective context":states[status])+(displayed?" · "+displayed:"");
    const inspector=$("inspection");
    const context=node("div");context.append(node("h3","","Objective limit"),node("p","",objective[2]));
    const alt=node("div");alt.append(node("h3","","Other ways to reach the effect"),node("p","",objective[3]+"."));
    const evidence=node("div");evidence.append(node("h3","","Evidence references"));
    if(refs.length){
      const list=node("div","detail-refs");
      refs.forEach(id=>list.append(node("span","tag",id+" · "+study.evidence[id])));
      evidence.append(list);
      if(["gate-b","gate-c"].includes(study.id)) evidence.append(node("p","","References come from the joined scenario assessment."));
    }else evidence.append(node("p","","No references included for this verdict."));
    const gaps=node("div");gaps.append(node("h3","","Evidence gaps"));
    if(missing.length){const list=node("ul");missing.forEach(x=>list.append(node("li","",x)));gaps.append(list);}
    else gaps.append(node("p","",status==="-"?"This study did not independently evaluate the selected claim.":probeNotes[study.id]));
    inspector.replaceChildren(context,alt,evidence,gaps);
  }
  function renderLens(study,g,metrics){
    const controls=$("lens-toolbar");controls.hidden=study.mode==="comparison";
    $("lens-context").textContent=study.mode==="comparison"?"Documented observations only.": "Toggle a lens to load its recorded ablation cell.";
    const list=$("lenses");list.replaceChildren();
    if(study.mode==="comparison"){
      list.append(node("p","","No subset estimates are available for this comparison."));
      return;
    }
    for(const k of study.lenses){
      const enabled=state.lenses.includes(k);
      const after=enabled?state.lenses.replace(k,""):order(study,state.lenses+k);
      const n=metrics[state.claim]?.[0];
      const m=g.rows[after]?.[0][state.cohort]?.[state.claim]?.[0];
      const gain=Number.isFinite(m)&&Number.isFinite(n)?m-n:null;
      const b=node("button","lens");b.type="button";b.title=model.lenses[k][1];
      const label=k==="W"&&["gate-b","gate-c"].includes(study.id)?"Workload and policy":model.lenses[k][0];
      b.setAttribute("aria-pressed",String(enabled));
      if(gain!==null) b.setAttribute("aria-description","Change when toggled: "+gain+" for "+claimLabel(study,state.claim));
      b.dataset.focus="lens-"+k;
      b.append(node("span","symbol",k),node("span","",label),
         node("span","delta",gain===null?"":(gain>0?"+":"")+gain));
      b.addEventListener("click",()=>set({lenses:after}));list.append(b);
    }
  }
  function renderCoverage(study,g,metrics){
    const out=$("coverage");out.replaceChildren();
    const score=metrics[state.claim];
    if(!score){out.append(node("p","stat-block","This study has no coverage estimate for the selected claim."));return;}
    const [n,d,a,f]=score;
    const card=node("div","stat-block");
    if(!d){card.append(node("strong","","No positive denominator"),node("p","","Coverage is unavailable for this cohort and claim."));}
    else {
      const large=node("div","stat-big",n+" / "+d);
      const suffix=node("span",""," "+(state.claim==="capture"?"seen":"confirmed"));large.append(suffix);
      const bar=node("div","bar");bar.setAttribute("aria-hidden","true");
      const fill=node("span");fill.style.width=(n/d*100)+"%";bar.append(fill);card.append(large,bar);
      if(a!==null) card.append(node("p","",a+" abstentions"+(f===null?"":" · "+f+" false confirmations")));
    }
    out.append(card);
    const min=g.minimum[state.cohort]?.[state.claim];
    const tip=node("div","minimum");tip.append(node("span","","Study minimum"));
    if(min?.length) min.forEach(v=>{
      const b=node("button","tag",shortMask(v));b.dataset.focus="minimum-"+v;b.title="Select this recorded minimum";
      b.addEventListener("click",()=>set({lenses:v}));tip.append(b);
    });
    else tip.append(node("strong","",min?"None qualified":"Not evaluated"));
    out.append(tip);
    if(study.arms){
      const other=study.groups.find(x=>x.profile===g.profile&&x.cutoff===g.cutoff&&x.arm!==g.arm);
      const otherScore=other?.rows[state.lenses]?.[0][state.cohort]?.[state.claim];
      if(otherScore) out.append(node("p","source-info","Other synthetic arm ("+other.arm+") "+otherScore[0]+" / "+otherScore[1]));
    }
  }
  function renderDiagnostic(study){
    const panel=$("diagnostic");panel.hidden=!study.diagnostic;
    if(!study.diagnostic)return;
    const d=study.diagnostic;
    const heading=node("div","panel-title");
    heading.append(node("h2","",d.title),node("span","tag measured","Measured diagnostic"));
    const body=node("div","body");
    const table=node("table","diagram-table");const head=node("thead");const h=node("tr");
    table.setAttribute("aria-label",d.title);
    ["Call variant","Reference trace","Selected runtime hook"].forEach(label=>{
      const cell=node("th","",label);
      cell.scope="col";
      h.append(cell);
    });
    head.append(h);table.append(head);const tb=node("tbody");
    d.labels.forEach((label,i)=>{
      const row=node("tr");[label,d.reference[i]+" / "+d.denominator,d.observed[i]+" / "+d.denominator]
        .forEach(v=>row.append(node("td","",v)));
      if(activeLesson==="observation"&&lessons[2].steps[lessonStep].diagnostic===i){
        row.classList.add("selected"); row.cells[0].append(node("span","tag","Selected"));
      }
      tb.append(row);
    });table.append(tb);body.append(table,node("p","",d.note));panel.replaceChildren(heading,body);
  }
  function renderAtlas(){
    const atlas=$("atlas");atlas.replaceChildren();
    for(const s of model.studies){
      const g=s.groups.at(-1);
      const cohort=Object.keys(s.cohorts)[0];
      const stats=g.rows[s.lenses][0][cohort].effect;
      const b=node("button","study-card");
      b.dataset.focus="study-"+s.id;b.setAttribute("aria-pressed",String(s.id===state.study));b.addEventListener("click",()=>set({study:s.id}));
      b.append(node("span","tag "+s.evidenceClass.toLowerCase(),s.evidenceClass),
        node("strong","",s.title),
        node("span","figure",stats[0]+" / "+stats[1]+" · "+claimLabel(s,"effect",cohort)),
        node("span","muted",s.cohorts[cohort]+(g.arm?" · Arm "+g.arm:"")));
      atlas.append(b);
    }
  }
  function render(){
    const retainedFocus=document.activeElement?.dataset.focus;
    const current=view(state);
    const {study,g,example,assessment,metrics}=current;
    renderLesson(current);
    selection($("study"),model.studies.map(s=>[s.id,s.title]),state.study);
    const objectives=unique(Object.values(study.cases).map(item=>item.objective));
    selection($("objective-filter"),[["all","All objectives"],...objectives.map(k=>[k,model.objectives[k][0]])],state.objectiveFilter);
    selection($("case"),Object.entries(study.cases).filter(([,v])=>state.objectiveFilter==="all"||v.objective===state.objectiveFilter)
              .map(([k,v])=>[k,v.title.replace(" workload","")+" ["+k+"]"]),state.case);
    const paths=unique(Object.values(study.cases).filter(item=>item.objective===example.objective).map(item=>item.path));
    $("path-box").hidden=paths.length<2;
    $("path-label").hidden=paths.length>1;
    selection($("path"),paths.map(k=>[k,model.paths[k]||k]),example.path);
    const layer={native:"Native evidence",augmented:"Native + supplemental",B:"B · With attribution",C:"C · Complete research"};
    selection($("profile"),unique(study.groups.map(r=>r.profile)).map(p=>[p,layer[p]||study.profileLabels?.[p]||p]),state.profile);
    selection($("cutoff"),unique(study.groups.filter(r=>r.profile===state.profile).map(r=>r.cutoff))
              .map(v=>[v,v===null?(study.mode==="comparison"?"Study reporting window":"Retrospective"):v<1000?v+" ms":v/1000+" s"]),state.cutoff);
    $("arm-box").hidden=!study.arms;
    if(study.arms) selection($("arm"),Object.entries(study.arms),state.arm);
    selection($("cohort"),Object.entries(study.cohorts),state.cohort);
    selection($("claim"),study.claims.map(k=>[k,claimLabel(study,k)]),state.claim);
    $("class").className="tag "+study.evidenceClass.toLowerCase();
    $("class").textContent=study.evidenceClass;
    $("description").textContent=study.description;
    renderGraph(study,example,assessment);
    renderLens(study,g,metrics);
    renderCoverage(study,g,metrics);
    renderDiagnostic(study);
    renderAtlas();
    const p=$("provenance");
    p.replaceChildren(node("strong","",study.source+". "),document.createTextNode(study.limit+" Revision "),
      node("code","mono",study.revision));
    if(retainedFocus) root.querySelector(`[data-focus="${CSS.escape(retainedFocus)}"]`)?.focus({preventScroll:true});
  }
  const bindings={study:"study",case:"case","objective-filter":"objectiveFilter",profile:"profile",cutoff:"cutoff",arm:"arm",cohort:"cohort",claim:"claim"};
  for (const [id,key] of Object.entries(bindings)) $(id).addEventListener("change",e=>{
    const val=e.target.value;
    set({[key]:key==="cutoff"?(val==="null"?null:Number(val)):val});
  });
  $("path").addEventListener("change",event=>{
    const {study,example}=view(state);
    const key=Object.keys(study.cases).find(k=>study.cases[k].objective===example.objective&&study.cases[k].path===event.target.value);
    if(key) set({case:key});
  });
  $("all").addEventListener("click",()=>set({lenses:view(state).study.lenses}));
  $("clear").addEventListener("click",()=>set({lenses:""}));
  root.querySelectorAll("[data-guide]").forEach(b=>b.addEventListener("click",()=>{
    const choice=choices[b.dataset.guide];
    activeLesson=null;
    state=reset(choice.study);
    set(choice);
  }));
  lessonTabs();
  render();

  const explorer=$("explorer");
  const presentation=$("lens-presentation");
  const showPresentation=$("lens-present");
  const dismissPresentation=$("lens-exit-present");
  showPresentation.addEventListener("click",()=>{
    $("lens-presentation-content").append(explorer);
    presentation.showModal();
    presentation.scrollTop=0;
  });
  dismissPresentation.addEventListener("click",()=>presentation.close());
  presentation.addEventListener("close",()=>{
    $("lens-home").prepend(explorer);
    showPresentation.focus({preventScroll:true});
  });
  for(const link of root.querySelectorAll("#lens-open-explorer, .graph-jumps a")){
    link.addEventListener("click",() => $(link.hash.slice(1)).focus({preventScroll:true}));
  }
  const skip = document.querySelector("#lens-skip");
  if (skip) skip.setAttribute("href", "#explorer");
  explorer.hidden=false;
  $("studies").hidden=false;
  showPresentation.hidden=false;
  $("lens-open-explorer").hidden=false;
  $("lens-load-status").hidden=true;
}

const root = document.querySelector("[data-lens-explorer]");
if (root) {
  const status = root.querySelector("#lens-load-status");
  status.textContent = "Loading study evidence…";
  initialize(root).catch(() => {
    status.textContent =
      "Study evidence could not be loaded. The Research page summarizes the findings.";
  });
}
