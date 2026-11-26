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
    causal:"Causal link", objective:"Adversary objective"};
  // Publication copy for the study cards and reader guidance. The dataset
  // still supplies each study ID, evidence class, references, and results.
  const studyCopy = {
    "gate-b": {
      title: "Host-write attribution",
      description: "The synthetic workloads take direct and delegated paths to the same host canary write.",
      source: "Gate B synthetic fixtures and replay",
      limit: "The fixtures model stronger identity and completion evidence than native collectors usually provide."
    },
    "gate-c": {
      title: "Host writes",
      description: "The helper record and host readback supported the delegated effect. The direct path lacked a verified link between the operation and the change to the file.",
      source: "Gate C canary-write lab and replay",
      limit: "The lab could not confirm any direct-path effects. It lacked evidence tying a completed direct operation to the file change."
    },
    "gate-c2": {
      title: "Linux downstream effects",
      description: "Different paths can change the same test record. Select an effect or a causal link to check the evidence for it.",
      source: "Gate C.2 lab runs and Linux write diagnostic",
      diagnosticTitle: "Linux write capture",
      diagnosticNote: "The reference trace and runtime hook ran separately, twice per variant. Reference tracing verified completion. The selected Tetragon hook missed both vectored variants.",
      limit: "The replay scored 44 trials. C2-01 had a partial boundary effect and no downstream invocation. The lab did not establish completion of any attacker objective."
    },
    "gate-c3": {
      title: "Linux write capture (A/B)",
      description: "Compare two modeled observers under the same confirmation rules. The second adds a kernel return observation.",
      source: "Gate C.3 synthetic A/B replay",
      limit: "The A/B results are synthetic. Live hook attachment, field availability, and collection cost remain untested."
    },
    windows: {
      title: "Windows child-process starts",
      description: "An independent process creation event and an exact instance match tie a child process to the request that started it.",
      source: "Measured Sysmon cohort",
      limit: "The lab used exact instance matches and markers. The separate WMI polling run did not adjudicate exact child starts. Production coverage was outside the test scope."
    },
    php: {
      title: "PHP file reads",
      description: "A child process and an in-process PHP worker read the same canary. The delegated test linked a job to a separate destination result.",
      source: "Instrumented PHP-FPM canary",
      limit: "Per-process tracing covered controlled file reads. Coverage was limited for runtime-only computation and operations inside the delegated worker."
    }
  };
  const lensHelp = {
    P: "Process lifecycle events.",
    W: "Workload lifetime and object identity.",
    K: "Kernel events for scoped operations, including return values when captured.",
    D: "Records of the delegated request, completion, or transaction.",
    A: "Applicable policy and the technical access available to the actor.",
    H: "Independent outcome evidence, such as host readback or a destination receipt."
  };
  const missingLabels = {
    "bound boundary effect and downstream causation": "Evidence tying the boundary effect to the downstream action.",
    "completed effect and applicable policy": "The completed effect and the policy that applies to it.",
    "exact actor lifetime": "The exact actor instance and its lifetime.",
    "exact originating workload": "The exact workload that initiated the operation.",
    "independent matching outcome": "An independent outcome record that matches the operation.",
    "native operation return": "A native event with the operation's return value.",
    "node or edge observation": "An observation supporting the node or link.",
    "separate boundary marker": "A separate marker for the boundary-policy effect.",
    "terminal broker result": "The broker's final result.",
    "unique completed operation": "Evidence of the specific operation and its completion.",
    "verification of objective completion": "Evidence that the attacker objective was met."
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
    {id:"convergence", label:"Same objective", heading:"Two ways to read the same file",
     context:"Start with the child process. Switch to the in-process PHP worker, then check the approved route. All three read the same canary.",
     steps:[
       {name:"Inspect the child process", point:{study:"php",case:"child",selected:"effect"}},
       {name:"Switch to in-process", point:{study:"php",case:"worker",selected:"effect"}},
       {name:"Check the approved read", point:{study:"php",case:"admin",selected:"authorization"}}
     ],
     result({study,example,assessment}) {
       if(study.id!=="php"||example.objective!=="file_read")return null;
       const outcome=claimValue(assessment,"effect")[0];
       const policy=claimValue(assessment,"authorization")[0];
       return ["Canary read "+states[outcome]+" · Authorization violation "+states[policy],
         "The read can look the same on an approved route. Use evidence about the request and the applicable policy before treating the read as a violation."];
     }},
    {id:"resilience", label:"Missing upstream", heading:"You can confirm the effect before you can link it",
     context:"In this measured helper case, start at 250 ms. Check the link again in the final replay, then turn off the lenses that tie the effect to the upstream action.",
     steps:[
       {name:"Check at 250 ms", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:250,selected:"causal"}},
       {name:"Include later records", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,selected:"causal"}},
       {name:"Keep only effect evidence", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                   cohort:"path/workload_delegated",claim:"effect",selected:"causal"}, applyMinimum:"effect"}
     ],
     result({study,assessment}) {
       if(study.id!=="gate-c2"||state.case!=="C2-02")return null;
       const effect = claimValue(assessment,"effect")[0];
       const boundary = claimValue(assessment,"boundary")[0];
       const causal = claimValue(assessment,"causal")[0];
       let reading = "Open a node or the causal link to see what evidence is missing in this view.";
       if (causal === "C") {
         reading = "Select the confirmed link to see the evidence tying the downstream effect to the earlier action.";
       } else if (effect === "C") {
         reading = "This view confirms the downstream effect. The evidence here leaves the causal link open.";
       }
       return [
         "Downstream effect "+states[effect]+" · Boundary "+states[boundary]+" · Causal link "+states[causal],
         reading
       ];
     }},
    {id:"observation", label:"Behavior vs. sensor", heading:"The write completed. The hook missed it.",
     context:"Compare what reference tracing and the runtime hook saw in separate runs of the same write variants. Then check what an extra observation could add in the synthetic comparison.",
     steps:[
       {name:"Inspect vectored writes", point:{study:"gate-c2",case:"C2-03",profile:"augmented",cutoff:null,selected:"operation"}, diagnostic:1},
       {name:"Compare the scalar control", point:{study:"gate-c2",case:"C2-03",profile:"augmented",cutoff:null,selected:"operation"}, diagnostic:2},
       {name:"Check the synthetic comparison", point:{study:"gate-c3",case:"R01",profile:"augmented",cutoff:null,arm:"B",claim:"capture",selected:"capture"}}
     ],
     result({study,assessment,metrics}) {
       if(study.id==="gate-c3"&&state.case==="R01"){
         const count=metrics.capture;
         return ["Modeled kernel capture "+states[claimValue(assessment,"capture")[0]]+(count?" · "+count[0]+" / "+count[1]+" eligible operations":""),
          "The second configuration adds a modeled kernel return event. Live hook attachment and capture recovery still need a lab test."];
       }
       if(study.id!=="gate-c2")return null;
       const d=study.diagnostic, i=lessons[2].steps[lessonStep].diagnostic??1;
       return [d.labels[i]+" · Reference "+d.reference[i]+" / "+d.denominator+
         " · Runtime hook "+d.observed[i]+" / "+d.denominator,
         i===2?"Both observers captured the scalar control in their own runs. The capture gap in this test was in the vectored writes.":
           "Reference tracing confirmed 2 of 2 writes for each vectored variant. In separate runs, the selected Tetragon hook captured 0 of 2 for each."];
     }},
    {id:"minimum", label:"Minimum evidence", heading:"Find the smallest set of lenses for the job",
     context:"Use the final replay of the measured helper cases. Check which lenses meet the study's coverage and negative-control criteria for the effect, then check the causal link.",
     steps:[
       {name:"Use the smallest set for the effect", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                 cohort:"path/workload_delegated",claim:"effect",selected:"effect"}, applyMinimum:"effect"},
       {name:"Check the link with the same lenses", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                            cohort:"path/workload_delegated",claim:"causal",selected:"causal"}, applyMinimum:"effect"},
       {name:"Use the smallest set for the link", point:{study:"gate-c2",case:"C2-02",profile:"augmented",cutoff:null,
                                                 cohort:"path/workload_delegated",claim:"causal",selected:"causal"}, applyMinimum:"causal"}
     ],
     result({study,g,metrics}) {
       if(study.id!=="gate-c2"||state.cohort!=="path/workload_delegated")return null;
       const count=metrics[state.claim], recorded=g.minimum[state.cohort]?.[state.claim];
       if(!count)return null;
       return [shortMask(state.lenses)+" · "+count[0]+" / "+count[1]+" "+claimLabel(study,state.claim).toLowerCase()+
         " · Minimum "+(recorded?.length?recorded.map(shortMask).join(" or "):"none qualified"),
         !recorded?.length?"Use the final replay with supplemental evidence to compare the recorded effect and causal minimums.":
         state.claim==="causal"?"In the final replay, the qualifying set adds workload and policy evidence to the lenses used for the effect.":
         "The effect minimum applies to these helper cases at this cutoff. Check authorization, attribution, and cause on their own evidence."];
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
    $("lesson-question").textContent=lesson.heading;
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
    const result=lesson.result(current)||["These settings are outside this lesson.",
      "Select a lesson step to restore its settings."];
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
  function shortMask(mask){return mask?mask.split("").join(" · "):"No lenses";}
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
    const bridge=node("article","","Boundary or shared step");
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
      graphButton(upstreamSupported?"Upstream policy":"Execution path",
      upstreamSupported?"Boundary-policy violation":example.path==="delegated"?"Helper handoff":"Request or worker",
      upstreamSupported?"boundary":"attribution",assessment));
    graph.append(upper);
    const es=node("div","edge-shell");
    const edge=claimValue(assessment,"causal")[0];
    const button=node("button","state","Causal link · "+states[edge]);
    button.dataset.focus="graph-causal";
    es.dataset.v=edge;button.dataset.v=edge;button.setAttribute("aria-pressed",String(state.selected==="causal"));
    button.addEventListener("click",()=>set({selected:"causal"}));
    es.append(button);graph.append(es);
    const lower=node("div","downstream");
    lower.append(graphButton("Observation","Operation visibility","operation",assessment),arrow(),
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
    $("graph-note").textContent="Arrows show the modeled path. Select the causal link to check what ties the upstream action to the effect.";
    const displayed=study.caseNotes?.[state.case];
    const [status,refs,missing]=claimValue(assessment,state.selected);
    $("inspect-title").textContent=state.selected==="path"?"Attack paths and controls":claimLabel(study,state.selected,example.cohort);
    $("inspect-status").textContent=(state.selected==="path"?"Path context":states[status])+(displayed?" · "+displayed:"");
    const inspector=$("inspection");
    const context=node("div");context.append(node("h3","","Limits of this evidence"),node("p","",objective[2]));
    const alt=node("div");alt.append(node("h3","","Other paths and controls"),node("p","",objective[3]+"."));
    const evidence=node("div");evidence.append(node("h3","","Evidence records"));
    if(refs.length){
      const list=node("div","detail-refs");
      refs.forEach(id=>list.append(node("span","tag",id+" · "+study.evidence[id])));
      evidence.append(list);
      if(["gate-b","gate-c"].includes(study.id)) evidence.append(node("p","","These references cover the case as a whole."));
    }else evidence.append(node("p","",study.mode==="comparison"?"This comparison reports counts without per-case evidence references.":"The replay lists no evidence references for this verdict."));
    const gaps=node("div");gaps.append(node("h3","","Evidence gaps"));
    if(missing.length){const list=node("ul");missing.forEach(x=>list.append(node("li","",missingLabels[x] || x)));gaps.append(list);}
    else gaps.append(node("p","",status==="-"?"This study did not assess this claim separately.":"The replay lists no missing evidence for this verdict."));
    inspector.replaceChildren(context,alt,evidence,gaps);
  }
  function renderLens(study,g,metrics){
    const controls=$("lens-toolbar");controls.hidden=study.mode==="comparison";
    $("lens-context").textContent=study.mode==="comparison"?"This comparison uses the reported observations.": "Turn lenses on or off to see what the replay confirms with that evidence.";
    const list=$("lenses");list.replaceChildren();
    if(study.mode==="comparison"){
      list.append(node("p","","The study did not replay telemetry subsets."));
      return;
    }
    for(const k of study.lenses){
      const enabled=state.lenses.includes(k);
      const after=enabled?state.lenses.replace(k,""):order(study,state.lenses+k);
      const n=metrics[state.claim]?.[0];
      const m=g.rows[after]?.[0][state.cohort]?.[state.claim]?.[0];
      const gain=Number.isFinite(m)&&Number.isFinite(n)?m-n:null;
      const b=node("button","lens");b.type="button";b.title=k==="W"&&["gate-b","gate-c"].includes(study.id)
        ? "Workload lifetime, object identity, and policy."
        : lensHelp[k] || model.lenses[k][1];
      const label=k==="W"&&["gate-b","gate-c"].includes(study.id)?"Workload and policy":model.lenses[k][0];
      b.setAttribute("aria-pressed",String(enabled));
      if(gain!==null) b.setAttribute("aria-description","Change in the count if you toggle this lens: "+gain);
      b.dataset.focus="lens-"+k;
      b.append(node("span","symbol",k),node("span","",label),
         node("span","delta",gain===null?"":(gain>0?"+":"")+gain));
      b.addEventListener("click",()=>set({lenses:after}));list.append(b);
    }
  }
  function renderCoverage(study,g,metrics){
    const out=$("coverage");out.replaceChildren();
    const score=metrics[state.claim];
    if(!score){out.append(node("p","stat-block","This study did not report coverage for this claim."));return;}
    const [n,d,a,f]=score;
    const card=node("div","stat-block");
    if(!d){card.append(node("strong","","No eligible positive cases"),node("p","","Choose another cohort or claim to view coverage."));}
    else {
      const large=node("div","stat-big",n+" / "+d);
      const suffix=node("span",""," "+(state.claim==="capture"?"seen":"confirmed"));large.append(suffix);
      const bar=node("div","bar");bar.setAttribute("aria-hidden","true");
      const fill=node("span");fill.style.width=(n/d*100)+"%";bar.append(fill);card.append(large,bar);
      if(a!==null) card.append(node("p","",a+" abstentions"+(f===null?"":" · "+f+" false confirmations")));
    }
    out.append(card);
    const min=g.minimum[state.cohort]?.[state.claim];
    const tip=node("div","minimum");tip.append(node("span","","Smallest qualifying set"));
    if(min?.length) min.forEach(v=>{
      const b=node("button","tag",shortMask(v));b.dataset.focus="minimum-"+v;b.title="Use this lens set";
      b.addEventListener("click",()=>set({lenses:v}));tip.append(b);
    });
    else tip.append(node("strong","",min?"None qualified":"Not evaluated"));
    out.append(tip);
    if(study.arms){
      const other=study.groups.find(x=>x.profile===g.profile&&x.cutoff===g.cutoff&&x.arm!==g.arm);
      const otherScore=other?.rows[state.lenses]?.[0][state.cohort]?.[state.claim];
      if(otherScore) out.append(node("p","source-info", "Synthetic setup "+other.arm+" · "+otherScore[0]+" / "+otherScore[1]));
    }
  }
  function renderDiagnostic(study){
    const panel=$("diagnostic");panel.hidden=!study.diagnostic;
    if(!study.diagnostic)return;
    const d=study.diagnostic;
    const heading=node("div","panel-title");
    const title = studyCopy[study.id]?.diagnosticTitle || d.title;
    heading.append(node("h2","",title),node("span","tag measured","Measured diagnostic"));
    const body=node("div","body");
    const table=node("table","diagram-table");const head=node("thead");const h=node("tr");
    table.setAttribute("aria-label",title);
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
    });
    table.append(tb);
    body.append(table,node("p","",studyCopy[study.id]?.diagnosticNote || d.note));
    panel.replaceChildren(heading,body);
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
        node("strong","",studyCopy[s.id]?.title || s.title),
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
    selection($("study"),model.studies.map(s=>[s.id,studyCopy[s.id]?.title || s.title]),state.study);
    const objectives=unique(Object.values(study.cases).map(item=>item.objective));
    selection($("objective-filter"),[["all","All objectives"],...objectives.map(k=>[k,model.objectives[k][0]])],state.objectiveFilter);
    selection($("case"),Object.entries(study.cases).filter(([,v])=>state.objectiveFilter==="all"||v.objective===state.objectiveFilter)
              .map(([k,v])=>[k,v.title.replace(" workload","")+" ["+k+"]"]),state.case);
    const paths=unique(Object.values(study.cases).filter(item=>item.objective===example.objective).map(item=>item.path));
    $("path-box").hidden=paths.length<2;
    $("path-label").hidden=paths.length>1;
    selection($("path"),paths.map(k=>[k,model.paths[k]||k]),example.path);
    const layer={native:"Native evidence",augmented:"Native + supplemental",B:"B · With attribution",C:"C · Full lab evidence"};
    selection($("profile"),unique(study.groups.map(r=>r.profile)).map(p=>[p,layer[p]||study.profileLabels?.[p]||p]),state.profile);
    selection($("cutoff"),unique(study.groups.filter(r=>r.profile===state.profile).map(r=>r.cutoff))
              .map(v=>[v,v===null?(study.mode==="comparison"?"Study reporting window":"Retrospective"):v<1000?v+" ms":v/1000+" s"]),state.cutoff);
    $("arm-box").hidden=!study.arms;
    if(study.arms) selection($("arm"),Object.entries(study.arms),state.arm);
    selection($("cohort"),Object.entries(study.cohorts),state.cohort);
    selection($("claim"),study.claims.map(k=>[k,claimLabel(study,k)]),state.claim);
    $("class").className="tag "+study.evidenceClass.toLowerCase();
    $("class").textContent=study.evidenceClass;
    $("description").textContent=studyCopy[study.id]?.description || study.description;
    renderGraph(study,example,assessment);
    renderLens(study,g,metrics);
    renderCoverage(study,g,metrics);
    renderDiagnostic(study);
    renderAtlas();
    const p=$("provenance");
    const copy = studyCopy[study.id] || study;
    p.replaceChildren(node("strong","",copy.source+". "),document.createTextNode(copy.limit+" Source revision "),
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
  status.textContent = "Loading study results…";
  initialize(root).catch(() => {
    status.textContent =
      "Could not load the study results. Open Research to read the findings.";
  });
}
