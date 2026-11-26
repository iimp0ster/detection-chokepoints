// Behavioral placement model. The source projection is used only by the lab panel.
// Model facts belong to the behavioral graph. Study verdicts are read separately below.
const behavior = {
  start:"start", goal:"goal", sourceRefs:{
    lab:{label:"Accepted PHP-FPM canary comparison",maturity:"Illustrative structure from measured cases"},
    definition:{label:"Prototype start and goal boundaries",maturity:"Modeled"},
    counterfactual:{label:"Cached copy outside the report and lab",maturity:"Hypothetical"},
  },
  startingFacts:{phpCode:true,canStartChild:true,workerFileRead:true,childFileRead:true},
  nodes: [
    {id:"start", label:"PHP request runs", role:"Starting state", source:"definition", wide:[10,48], mobile:[50,10], reveal:1},
    {id:"child", label:"Start a child", role:"Execution interaction", source:"lab", wide:[33,23], mobile:[24,33], reveal:1, place:true},
    {id:"inproc", label:"Run inside PHP", role:"Alternative interaction", source:"lab", wide:[33,74], mobile:[76,33], reveal:3, place:true},
    {id:"file", label:"Read the file", role:"Data access interaction", source:"lab", wide:[61,30], mobile:[24,59], reveal:2, place:true},
    {id:"cache", label:"Read the cached copy", role:"Hypothetical interaction", source:"counterfactual", wide:[61,77], mobile:[76,59], reveal:5, variant:true, place:true},
    {id:"goal", label:"Data available to code", role:"Objective state", source:"definition", wide:[89,48], mobile:[50,86], reveal:2}
  ],
  edges: [
    {id:"start-child", from:"start", to:"child", label:"Request starts a child", requiresAll:["phpCode","canStartChild"], place:true, source:"lab"},
    {id:"start-inproc", from:"start", to:"inproc", label:"Request stays inside PHP", requiresAll:["phpCode"], branch:"inproc", place:true, source:"lab"},
    {id:"child-file", from:"child", to:"file", label:"Child route reaches file read", requiresAll:["childFileRead"], place:true, source:"lab"},
    {id:"inproc-file", from:"inproc", to:"file", label:"PHP route reaches file read", requiresAll:["workerFileRead"], branch:"inproc", place:true, source:"lab"},
    {id:"inproc-cache", from:"inproc", to:"cache", label:"PHP route reads cached copy", requiresAll:["sameCopy","cacheAccess"], branch:"whatif", place:true, source:"counterfactual"},
    {id:"file-goal", from:"file", to:"goal", label:"File read supplies the data", requiresAll:[], source:"definition"},
    {id:"cache-goal", from:"cache", to:"goal", label:"Cached copy supplies the same data", requiresAll:[], branch:"whatif", source:"counterfactual"}
  ],
};

function reachable(graph, removedNodes=new Set(), removedEdges=new Set()){
  if(removedNodes.has(graph.start))return new Set();
  const reached=new Set([graph.start]), queue=[graph.start];
  for(const vertex of queue){
    for(const edge of graph.edges){
      if(edge.from!==vertex||reached.has(edge.to)||removedNodes.has(edge.to)||removedEdges.has(edge.id))continue;
      reached.add(edge.to);
      queue.push(edge.to);
    }
  }
  return reached;
}
function pathList(graph){
  const result=[];
  function visit(vertices,edges){
    const last=vertices.at(-1);
    if(last===graph.goal){result.push({nodes:vertices,edges});return;}
    for(const edge of graph.edges){
      if(edge.from===last&&!vertices.includes(edge.to))visit([...vertices,edge.to],[...edges,edge.id]);
    }
  }
  visit([graph.start],[]);
  return result;
}
function* combinations(ids,size,position=0,prefix=[]){
  if(size===0){yield prefix;return;}
  for(let i=position;i<=ids.length-size;i++)yield* combinations(ids,size-1,i+1,[...prefix,ids[i]]);
}
function reachesGoal(graph,kind,removed){
  return (kind==="nodes"?reachable(graph,removed):reachable(graph,new Set(),removed)).has(graph.goal);
}
function smallestCuts(graph,kind){
  if(!reachable(graph).has(graph.goal))return null;
  const eligible=graph[kind].filter(item=>item.place).map(item=>item.id);
  for(let size=1;size<=eligible.length;size++){
    const cuts=[];
    for(const part of combinations(eligible,size))if(!reachesGoal(graph,kind,new Set(part)))cuts.push(part);
    if(cuts.length)return cuts;
  }
  return [];
}
function analyze(model,step,variant,facts,kind,detectors,blocks){
  const nodes=model.nodes.filter(node=>node.reveal<=step&&(!node.variant||variant));
  const present=new Set(nodes.map(item=>item.id));
  const drawn=model.edges.filter(edge=>present.has(edge.from)&&present.has(edge.to));
  const edges=drawn.filter(edge=>edge.requiresAll.every(fact=>facts[fact]===true));
  const graph={start:model.start,goal:model.goal,nodes,edges};
  const paths=pathList(graph);
  const dom=paths.length?nodes.filter(item=>item.place&&!reachesGoal(graph,"nodes",new Set([item.id]))):[];
  return {nodes,drawn,edges,paths,dom,
    hits:paths.filter(path=>path[kind].some(id=>detectors.has(id))).length,
    reachable:reachesGoal(graph,kind,blocks),
    nodeCuts:smallestCuts(graph,"nodes"),edgeCuts:smallestCuts(graph,"edges")};
}

function initializePlacement(container, projection, onExit){
  const lesson=[
    {level:0,title:"Recall the threat",copy:"Microsoft reported web shells that activated when a PHP request carried the expected cookie.",hint:"The exercise starts after code is already running for a request. It follows a narrower data-access objective."},
    {level:2,title:"Follow the child route",copy:"The request starts a child process. The child reads the designated file and makes the data available to that code.",hint:"",focus:["child","file"]},
    {level:3,title:"Find the shared interaction",copy:"The same file can be read inside the PHP worker. Select a node to see which routes pass through it.",hint:"Try the child start first. Clear it, then select the file read.",focus:["file","inproc"]},
    {level:5,title:"Challenge the file read",copy:"Both original routes need the file read. Consider an alternative that gives the code the same data.",hint:"Open the hypothetical route, check its two assumptions, then add it.",focus:["cache"]},
    {level:6,title:"Cover the routes with a set",copy:"With the cached copy available, the file read misses one route. Select another location to cover that route.",hint:"Use the smallest sets when you want to compare placements.",focus:["file","cache"]},
    {level:7,title:"Try blocking an interaction",copy:"Switch between Detect and Prevent. Try blocking the file read, then block the cached-copy read too.",hint:"Detect marks where you could look. Prevent simulates what happens when an interaction is blocked.",focus:["file","cache"]},
    {level:7,title:"Check what the evidence supports",copy:"A location on a modeled route tells you where to look. Verify the operation, actor and policy before calling it a prohibited read.",hint:"The measured results below use a separate canary comparison.",focus:["file"]}
  ];
  const make=(tag,text="",className="")=>{
    const element=document.createElement(tag);
    element.textContent=text;
    element.className=className;
    return element;
  };
  const byId=id=>container.querySelector("#place-"+id);
  const start=()=>({index:0,explore:false,mode:"detect",kind:"nodes",openVariant:false,variant:false,
    sameCopy:true,cacheAccess:true,showCuts:false,cutIndex:0,
    detect:{nodes:new Set(),edges:new Set()},prevent:{nodes:new Set(),edges:new Set()}});
  let state=start();
  const empty=new Set();
  const titles=Object.fromEntries(["nodes","edges"].map(kind=>[kind,Object.fromEntries(behavior[kind].map(x=>[x.id,x.label]))]));
  const routeName=path=>path.nodes.includes("cache")?"Cached-copy route":path.nodes.includes("child")?"Child-process route":"In-process file route";
  const using=(path,kind,selection)=>path[kind].some(id=>selection.has(id));

  const map=byId("map");
  const tiles=new Map(), connectors=new Map();
  const roleText={start:"Starting state",goal:"Objective"};
  const symbols={detect:["D","Detector placed"],prevent:["P","Simulated block"],minimum:["M","Part of smallest set"]};
  const ports={
    "start-child":[[-10,0,-6],[-16,0,-6]],
    "start-inproc":[[10,0,6],[16,0,6]],
    "child-file":[[-9,-9,0],[-10,-10,0]],
    "inproc-file":[[-9,9,0],[-14,14,0]],
    "inproc-cache":[[9,9,0],[10,10,0]],
    "file-goal":[[0,-10,-6],[0,-16,-6]],
    "cache-goal":[[0,10,6],[0,16,6]]
  };

  function initGraph(){
    const ns="http://www.w3.org/2000/svg";
    const svg=document.createElementNS(ns,"svg");
    svg.classList.add("placement-connectors");
    svg.setAttribute("aria-hidden","true");
    svg.setAttribute("preserveAspectRatio","none");
    for(const edge of behavior.edges){
      const group=document.createElementNS(ns,"g");
      group.setAttribute("class","edge "+(edge.branch||""));
      group.dataset.edge=edge.id;
      const line=document.createElementNS(ns,"path"), head=document.createElementNS(ns,"path");
      line.classList.add("placement-wire");
      head.classList.add("placement-head");
      group.append(line,head);
      svg.append(group);
      connectors.set(edge.id,{line,head});
    }
    map.append(svg);
    for(const n of behavior.nodes){
      const item=make(n.place?"button":"div","","tile");
      item.dataset.id=n.id;
      item.append(make("strong",n.label));
      if(roleText[n.id])item.append(make("small",roleText[n.id],"placement-role"));
      item.append(make("span","","placement-marks"));
      if(n.place){
        item.type="button";
        item.addEventListener("click",()=>togglePlacement(n.id));
      }
      map.append(item);
      tiles.set(n.id,item);
    }
    return svg;
  }

  let frame=0;
  function scheduleConnectors(){
    if(!frame)frame=requestAnimationFrame(()=>{
      frame=0;
      drawConnectors();
    });
  }

  function drawConnectors(){
    const rect=map.getBoundingClientRect();
    if(!rect.width||!rect.height)return;
    const vertical=getComputedStyle(map).getPropertyValue("--placement-flow").trim()==="vertical";
    const scale=window.devicePixelRatio||1;
    const snap=value=>Math.round(value*scale)/scale;
    svg.setAttribute("viewBox",`0 0 ${rect.width} ${rect.height}`);
    const anchors=new Map();
    for(const [id,item] of tiles){
      if(item.hidden)continue;
      const {left,right,top,bottom}=item.getBoundingClientRect();
      anchors.set(id,vertical?
        {start:bottom-rect.top,end:top-rect.top,cross:(left+right)/2-rect.left}:
        {start:right-rect.left,end:left-rect.left,cross:(top+bottom)/2-rect.top});
    }
    // Every branch has a reserved position and a separate port where routes converge.
    // Express bends in the gap between levels so the paths never run through a tile.
    for(const edge of behavior.edges){
      const from=anchors.get(edge.from), to=anchors.get(edge.to);
      if(!from||!to)continue;
      const [fromPort,toPort,lane]=ports[edge.id][vertical?1:0];
      const start=snap(from.start+1), end=snap(to.end-8);
      const mid=snap((start+end)/2+lane);
      const first=snap(from.cross+fromPort), last=snap(to.cross+toPort);
      const point=(along,cross)=>vertical?`${cross} ${along}`:`${along} ${cross}`;
      const {line,head}=connectors.get(edge.id);
      line.setAttribute("d",`M ${point(start,first)} L ${point(mid,first)} L ${point(mid,last)} L ${point(end,last)}`);
      head.setAttribute("d",`M ${point(end-6,last-3.5)} L ${point(end,last)} L ${point(end-6,last+3.5)}`);
    }
  }

  function renderMarks(item,markers){
    const signature=markers.join(" ");
    const holder=item.querySelector(".placement-marks");
    if(holder.dataset.markers===signature)return;
    holder.dataset.markers=signature;
    holder.replaceChildren(...markers.map(kind=>{
      if(kind==="unavailable")return make("span","Unavailable","placement-unavailable");
      const [letter,description]=symbols[kind];
      const mark=make("span",letter,"placement-marker is-"+kind);
      mark.setAttribute("aria-hidden","true");
      const text=make("span",description,"walk-sr");
      const wrap=make("span");
      wrap.append(mark,text);
      return wrap;
    }));
  }

  function context(){
    const step=lesson[state.index];
    const canPlace=state.explore||state.index>=2;
    const canPrevent=state.explore||state.index>=5;
    const mode=canPrevent?state.mode:"detect";
    const kind=state.explore?state.kind:"nodes";
    const variant=(state.explore||state.index>=3)&&state.variant;
    const level=state.explore?7:step.level;
    const result=analyze(behavior,level,variant,{...behavior.startingFacts,sameCopy:state.sameCopy,cacheAccess:state.cacheAccess},
      kind,canPlace?state.detect[kind]:empty,canPrevent?state.prevent[kind]:empty);
    const selection=canPlace?state[mode][kind]:empty;
    const cuts=kind==="nodes"?result.nodeCuts:result.edgeCuts;
    const cut=state.showCuts&&cuts?.length?cuts[state.cutIndex%cuts.length]:null;
    return {step,canPlace,canPrevent,mode,kind,variant,result,selection,cuts,cut};
  }

  function togglePlacement(id){
    const {selection}=context();
    if(selection.has(id))selection.delete(id);
    else selection.add(id);
    render();
  }

  function renderGraph(view){
    const {step,canPlace,mode,kind,result,selection,cut}=view;
    const shown=new Set(result.nodes.map(n=>n.id)), drawn=new Set(result.drawn.map(e=>e.id));
    const enabled=new Set(result.edges.map(e=>e.id));
    const affected=result.paths.filter(path=>using(path,kind,selection));
    const hits=new Set(affected.flatMap(path=>path.edges));
    const anyHits=affected.length>0;
    map.dataset.mode=mode;
    for(const item of map.querySelectorAll(".tile")){
      const id=item.dataset.id;
      const chosen=kind==="nodes"&&selection.has(id);
      const suggested=kind==="nodes"&&Boolean(cut?.includes(id));
      const unavailable=id==="cache"&&!enabled.has("inproc-cache");
      item.hidden=!shown.has(id);
      item.classList.toggle("current",Boolean(step.focus?.includes(id)));
      item.classList.toggle("cut",suggested);
      item.classList.toggle("unavailable",unavailable);
      renderMarks(item,[chosen?mode:"",suggested?"minimum":"",unavailable?"unavailable":""].filter(Boolean));
      if(item instanceof HTMLButtonElement){
        item.disabled=!canPlace||kind!=="nodes"||unavailable;
        item.setAttribute("aria-pressed",String(chosen));
      }
    }
    for(const item of map.querySelectorAll("[data-edge]")){
      const id=item.dataset.edge;
      item.style.visibility=drawn.has(id)?"visible":"hidden";
      item.classList.toggle("hit",hits.has(id));
      item.classList.toggle("dim",anyHits&&!hits.has(id));
      item.classList.toggle("cut",kind==="edges"&&Boolean(cut?.includes(id)));
      item.classList.toggle("unavailable",!enabled.has(id));
      item.classList.toggle("block-point",mode==="prevent"&&kind==="edges"&&selection.has(id));
    }
    byId("key").hidden=!canPlace;
    byId("relationships").replaceChildren(...result.drawn.map(edge=>make("li",edge.label+
      (enabled.has(edge.id)?"":" · Preconditions unmet"))));
  }

  function renderResults(view){
    const {mode,result,kind,variant,selection,cuts,cut}=view;
    const total=result.paths.length;
    const affected=result.paths.filter(path=>using(path,kind,selection)).length;
    const matchingMinimum=Boolean(cuts?.some(set=>set.length===selection.size&&set.every(id=>selection.has(id))));
    const suffix=matchingMinimum?" · Smallest qualifying set":"";
    const status=byId("status");
    status.dataset.mode=mode;
    status.textContent=mode==="detect"?affected+" of "+total+" modeled paths pass a selected location"+suffix:
      "Objective "+(result.reachable?"reachable":"unreachable")+" in simulation · "+affected+" of "+total+" modeled paths blocked"+suffix;
    const routes=byId("routes");
    routes.dataset.mode=mode;
    const chips=result.paths.map(path=>{
      const active=using(path,kind,selection);
      const className=[active?"hit":"",path.nodes.includes("cache")?"hypothetical":""].filter(Boolean).join(" ");
      const item=make("li","",className);
      item.append(make("strong",routeName(path)),make("small",mode==="detect"?
        (active?"Intersects selection":"No selected location"):(active?"Blocked in simulation":"Open in simulation")));
      return item;
    });
    if(variant&&!result.paths.some(path=>path.nodes.includes("cache"))){
      const item=make("li","","hypothetical");
      item.append(make("strong","Cached-copy route"),make("small","Unavailable · A prerequisite is missing"));
      chips.push(item);
    }
    routes.replaceChildren(...chips);
    const choices=cut?cuts.length:0;
    byId("cuts").textContent=state.showCuts?"Hide smallest sets":"Show smallest sets";
    byId("cuts").setAttribute("aria-expanded",String(state.showCuts));
    byId("next-cut").hidden=choices<2;
    byId("cut-note").textContent=cut?"Set "+(state.cutIndex%choices+1)+" of "+choices+" · "+cut.map(id=>titles[kind][id]).join(" + "):
      state.showCuts?"No set qualifies under these conditions.":"";
    byId("dominance").textContent=result.dom.length?
      "An interaction that every route to the objective must pass is a dominator. Here that is "+result.dom.map(n=>n.label.toLowerCase()).join(", ")+
      ".":"No eligible interaction dominates the objective. Each can be skipped on at least one modeled route.";
    const list=sets=>sets?.length?sets[0].length:"none";
    byId("cut-detail").textContent="A minimum cut is the smallest eligible set that intersects every route. Size "+
      list(result.nodeCuts)+" for interactions and "+list(result.edgeCuts)+" for transitions.";
  }

  function renderAdvanced({mode,kind,result,selection,cut}){
    const available=kind==="nodes"?result.nodes:result.drawn;
    byId("kind").value=state.kind;
    byId("advanced-legend").textContent=mode==="detect"?"Detector locations":"Simulated blocks";
    const container=byId("advanced-options");
    const items=available.filter(item=>item.place);
    const signature=kind+":"+items.map(item=>item.id).join(",");
    if(container.dataset.signature!==signature){
      container.dataset.signature=signature;
      container.replaceChildren(...items.map(item=>{
        const label=make("label");
        const input=make("input");
        input.type="checkbox";input.value=item.id;
        input.addEventListener("change",()=>togglePlacement(item.id));
        label.append(input,make("span",item.label),make("small","","min-mark"));
        return label;
      }));
    }
    for(const input of container.querySelectorAll("input")){
      input.checked=selection.has(input.value);
      input.disabled=input.value==="cache"&&!result.edges.some(x=>x.id==="inproc-cache")||
        kind==="edges"&&!result.edges.some(x=>x.id===input.value);
      input.closest("label").querySelector(".min-mark").textContent=cut?.includes(input.value)?"· Smallest set":"";
    }
  }

  const evidenceNames={C:"Confirmed",O:"Observed",N:"No match","-":"Not adjudicated"};
  function renderLab(){
    byId("evidence").hidden=!byId("evidence-on").checked;
    const row=projection.cases[byId("evidence-case").value];
    const labels={operation:"Operation visibility",effect:"Completed designated file read",attribution:"Exact attribution",authorization:"Authorization violation"};
    byId("evidence-graph").replaceChildren(...Object.entries(labels).map(([key,label])=>{
      const line=make("p","","claim placement-row between");
      const code=row.verdicts[key];
      line.append(make("span",label),make("strong",evidenceNames[code],code==="C"?"confirmed":""));
      return line;
    }));
  }

  function render(){
    const view=context(), {step,canPlace,canPrevent,mode,result}=view;
    const showVariant=state.explore||state.index>=3;
    const showCuts=state.explore||state.index>=4;
    byId("progress").textContent=state.explore?"Explore placements":"Step "+(state.index+1)+" of "+lesson.length;
    byId("heading").textContent=state.explore?"Compare placements":step.title;
    const cacheEnabled=result.paths.some(path=>path.nodes.includes("cache"));
    let copy=step.copy;
    if(state.index===4&&!cacheEnabled){
      copy="Both current routes pass the file read. Enable the hypothetical route to try a placement that spans multiple interactions.";
    }else if(state.index===4&&result.hits===result.paths.length){
      copy="Every modeled route intersects a selected location. Compare your placement with the smallest sets.";
    }else if(state.index===4&&!state.detect.nodes.has("file")){
      copy="Select Read the file to mark the two file-read routes, then add a location for the cached-copy route.";
    }
    if(state.index===5&&!cacheEnabled){
      copy="Try blocking the file read. Enable the hypothetical route to see what stays reachable when it is blocked.";
    }
    byId("copy").textContent=state.explore?"Select an interaction on the graph, or open advanced placement to try transitions.":copy;
    byId("hint").textContent=state.explore?"Switch modes to keep observations and simulated blocks separate.":step.hint;
    byId("explore").textContent=state.explore?"Return to the walkthrough":"Explore placements";
    byId("explore").setAttribute("aria-pressed",String(state.explore));
    byId("board").hidden=result.nodes.length===0;
    byId("modes").hidden=!canPlace;
    byId("prevent").hidden=!canPrevent;
    byId("detect").setAttribute("aria-pressed",String(mode==="detect"));
    byId("prevent").setAttribute("aria-pressed",String(mode==="prevent"));
    byId("clear").disabled=view.selection.size===0;
    byId("readout").hidden=!canPlace;
    byId("variant-controls").hidden=!showVariant;
    byId("variant").textContent=state.openVariant?"Hide route assumptions":"Consider a cached copy";
    byId("variant").setAttribute("aria-expanded",String(state.openVariant));
    byId("prerequisites").hidden=!state.openVariant;
    byId("variant-add").textContent=state.variant?"Remove hypothetical route":"Add hypothetical route";
    byId("variant-add").setAttribute("aria-pressed",String(state.variant));
    byId("sameCopy").checked=state.sameCopy;
    byId("cacheAccess").checked=state.cacheAccess;
    byId("variant-note").textContent=state.variant?
      (state.sameCopy&&state.cacheAccess?"Both assumptions hold. The modeled route is enabled.":"The modeled route is unavailable while either assumption is missing."):
      "The report and the PHP lab did not establish this route.";
    byId("cut-tools").hidden=!showCuts;
    byId("analysis").hidden=!showCuts;
    byId("advanced").hidden=!state.explore;
    byId("nav").hidden=state.explore;
    byId("back").disabled=state.index===0;
    byId("next").hidden=state.index===lesson.length-1;
    byId("skip").hidden=state.index===lesson.length-1;
    byId("lab").hidden=!state.explore&&state.index!==lesson.length-1;
    renderGraph(view);
    renderResults(view);
    scheduleConnectors();
    if(state.explore)renderAdvanced(view);
  }

  function focus(id){
    const element=byId(id);
    element.focus({preventScroll:true});
    const goal=container.querySelector(".placement-objective");
    element.style.scrollMarginTop=(goal.offsetHeight+parseFloat(getComputedStyle(goal).top)+12)+"px";
    element.scrollIntoView({block:"start"});
  }
  function go(index){
    if(!state.explore&&index===5&&state.index<5)state.mode="prevent";
    state.index=index;
    state.showCuts=false;
    state.cutIndex=0;
    render();
    focus(index===lesson.length-1?"lab-title":"heading");
  }
  const on=(id,fn,type="click")=>byId(id).addEventListener(type,fn);
  const svg=initGraph();
  new ResizeObserver(scheduleConnectors).observe(map);
  for(const [id,entry] of Object.entries(projection.cases)){
    const option=make("option",entry.label);option.value=id;byId("evidence-case").append(option);
  }
  byId("lab-count").textContent=projection.confirmed+" of "+projection.eligible+" prohibited canary reads confirmed across the study.";
  byId("study-revision").textContent="PHP study revision "+projection.revision;
  on("exit",onExit);
  on("explore",()=>{state.explore=!state.explore;state.showCuts=false;state.cutIndex=0;render();});
  on("detect",()=>{state.mode="detect";render();});
  on("prevent",()=>{state.mode="prevent";render();});
  on("clear",()=>{context().selection.clear();render();byId(context().mode).focus();});
  on("variant",()=>{state.openVariant=!state.openVariant;render();});
  on("variant-add",()=>{
    state.variant=!state.variant;
    state.cutIndex=0;
    if(!state.variant){
      for(const mode of ["detect","prevent"]){
        state[mode].nodes.delete("cache");
        state[mode].edges.delete("inproc-cache");
      }
    }
    render();
  });
  for(const key of ["sameCopy","cacheAccess"]){
    on(key,event=>{
      state[key]=event.target.checked;
      if(!state.sameCopy||!state.cacheAccess){
        for(const mode of ["detect","prevent"]){
          state[mode].nodes.delete("cache");
          state[mode].edges.delete("inproc-cache");
        }
      }
      state.cutIndex=0;
      render();
    },"change");
  }
  on("cuts",()=>{state.showCuts=!state.showCuts;state.cutIndex=0;render();});
  on("next-cut",()=>{state.cutIndex++;render();});
  on("kind",event=>{state.kind=event.target.value;state.cutIndex=0;render();},"change");
  on("back",()=>go(state.index-1));
  on("next",()=>go(state.index+1));
  on("skip",()=>go(lesson.length-1));
  on("replay",()=>{
    state=start();byId("evidence-on").checked=true;byId("evidence-case").selectedIndex=0;byId("analysis").open=false;byId("advanced").open=false;
    renderLab();go(0);
  });
  on("evidence-on",renderLab,"change");
  on("evidence-case",renderLab,"change");
  renderLab();
  return {
    open(){
      state=start();
      byId("evidence-on").checked=true;
      byId("evidence-case").selectedIndex=0;
      byId("analysis").open=false;
      byId("advanced").open=false;
      renderLab();
      render();
      focus("heading");
    }
  };
}

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

  // Lesson frames describe behavior. Evidence selections only read the study projection.
  const helperCase = {study:"gate-c2",case:"C2-02",profile:"augmented",
    cohort:"path/workload_delegated",claim:"effect",selected:"effect"};
  const lessons = [
    {
      id:"convergence", label:"PHP web shells", heading:"Cookie-controlled PHP web shells",
      source:["Microsoft · April 2, 2026",$("place-source").href],
      threat:"Microsoft reported PHP web shells that activated on a cookie in the request. In one compromise, a scheduled job restored the loader after removal, keeping remote code execution available. The lab below follows a narrower file-read objective.",
      objectiveLabel:"Lab objective",
      objective:"Read the designated file after a request reaches PHP.",
      nodes:{i:["Canary request","Lab origin"],p:["PHP worker","Request handler"],q:["Child process","Child route"],
        a:["In-process read","Alternative route"],s:["Same file read","Shared interaction"]},
      edges:[["i","p"],["p","q"],["q","s"],["p","a","alternative"],["a","s","alternative"]],
      steps:[
        {title:"Start with the web shell"},
        {title:"Follow the request", show:"i p", copy:"Microsoft's shell checked the incoming cookie before running code. Here a canary request reaches PHP-FPM. The lab did not reproduce the cookie check."},
        {title:"Follow the child process", show:"q", copy:"In the first route, the worker starts a child. Process lineage can show the handoff. The file access is still a separate question."},
        {title:"Check the read completed", show:"s", copy:"The child reads the designated canary. The file identity and read result matter when the claim is a completed read."},
        {title:"Keep the work inside PHP", show:"a s", phase:1, copy:"The worker can read the same file in-process. A detector looking for a child sees only the first route."},
        {title:"What has to happen either way?", focus:"s", copy:"Compare the two routes to the same file.", hint:"A process can change. Both routes must successfully read the designated file to meet this objective."},
        {title:"Name the shared interaction", focus:"s", candidate:"s", copy:"A chokepoint is an interaction the actor must complete to reach a defined objective. The designated file read is a candidate for these two paths.", catalog:true},
        {title:"Test the detection", phase:2, focus:"s", activity:"php", copy:"Pick a type of record to see where it helps. The PHP study did not replay subsets."},
        {title:"Review the lab results", activity:"php", findings:true, focus:"s", copy:"Compare the prohibited reads with the approved control."}
      ],
      catalog:["web-shells","Web Shell Persistence catalog entry"],
      limits:"The lab used an instrumented canary file. It did not replay the incident, test cookie activation or persistence, or establish disclosure of real data.",
      apply:"Keep the child-process hunt for the route it covers. To confirm a read, bind the event to the exact file and actor, then check the applicable policy."
    },{
      id:"resilience", label:"Container credential access", heading:"Two routes to credential material",
      source:["Sysdig · June 4, 2026","https://www.sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane-ai-agent-driven-container-escape"],
      threat:"Sysdig reported a compromised application workload using Docker management access to read host credential files. The workload's service account was also used to read Kubernetes Secrets.",
      objective:"Collect credential material. The returned data supports this inference.",
      nodes:{i:["Compromised workload","Reported origin"],p:["Docker management","Host route"],q:["Host credential files","File read"],
        a:["Kubernetes API","Alternative route"],b:["Namespace Secrets","API read"]},
      edges:[["i","p"],["p","q"],["i","a","alternative"],["a","b","alternative"]],
      steps:[
        {title:"Start with the compromised workload"},
        {title:"Follow the runtime request", show:"i p", copy:"Sysdig documented access to Docker from the workload. The runtime action came before the read."},
        {title:"Follow the host effect", show:"q", copy:"The operation returned host credential material. A record of the read and a record tying it to the original workload answer separate questions."},
        {title:"Follow the management-plane route", show:"a", phase:1, copy:"The same report describes a service-account token used against the Kubernetes API. This route uses API authority."},
        {title:"What do the routes share?", show:"b", focus:"q b", copy:"Both routes read a protected resource, through different interfaces and against different objects. The API read alone leaves host access unresolved.", hint:"Start with evidence at the resource. Add caller and route-specific records when you need attribution."},
        {title:"Check the downstream finding", phase:2, focus:"q b", activity:"resilience", copy:"Switch the receipt cutoff, then remove upstream evidence. Watch which claims still have support."},
        {title:"Review the lab results", activity:"resilience", findings:true, focus:"q b", copy:"Compare the effect and the causal link. Each has its own evidence."}
      ],
      limits:"The measured helper case changed an inert host record. It did not read credentials or test Docker or Kubernetes access. This experiment leaves the container-escape candidate unresolved.",
      apply:"Investigate a confirmed sensitive read even when attribution is open. Report an originating workload or a boundary crossing when the records support it."
    },{
      id:"observation", label:"Linux process hiding", heading:"Process hiding after a container compromise",
      source:["Aqua Nautilus · August 26, 2021","https://www.aquasec.com/blog/advanced-persistent-threat-techniques-container-attacks/"],
      threat:"Aqua analyzed scripts from a container campaign with a kernel rootkit and a user-space fallback that changed process-listing utilities.",
      objective:"Keep a miner out of process listings, as described by Aqua.",
      nodes:{i:["Host foothold","Reported context"],p:["Kernel module","Kernel route"],q:["Filtered kernel results","Modeled effect"],
        a:["Replace a utility","Fallback route"],b:["Filtered utility output","Modeled effect"]},
      narrowSlots:{q:[24,66],b:[76,66]},
      edges:[["i","p"],["p","q"],["i","a","alternative"],["a","b","alternative"]],
      steps:[
        {title:"Start with the concealment objective"},
        {title:"Follow the kernel branch", show:"i p", copy:"The analyzed script has a kernel module branch after the host foothold."},
        {title:"Follow the effect on process listings", show:"q", copy:"The module can change what process enumeration returns. That objective can be met while the listing utility on disk stays intact."},
        {title:"Follow the fallback", show:"a", phase:1, copy:"The script also has a fallback that replaces process-listing utilities. The replacement is a necessary interaction for this branch."},
        {title:"Compare the two effects", show:"b", candidate:"a", copy:"Both branches aim to alter what the operator sees. Only the replacement branch requires a change to the utility on disk."},
        {title:"Place an observer", phase:2, activity:"observation", focus:"a", copy:"Pick a place to look before checking the diagnostic. What claim could its records support?"},
        {title:"Review the lab results", activity:"observation", findings:true, focus:"a", copy:"The diagnostic compared two observers and four harmless write variants in separate runs."}
      ],
      limits:"The diagnostic used no rootkit or utility replacement. It establishes a write-capture gap for one configuration. Gate C.3 models an added return observation and remains synthetic.",
      apply:"Verify coverage with known-good writes and validate expected package updates before attributing a utility change."
    },{
      id:"minimum", label:"Docker SSH backdoors", heading:"Linking SSH trust changes to a Docker intrusion",
      source:["Datadog Security Labs · February 1, 2024","https://securitylabs.datadoghq.com/articles/analysis-of-teamtnt-doppelganger/"],
      threat:"Datadog reported a campaign against exposed Docker APIs. The persistence scripts it analyzed added SSH keys and changed SSH settings.",
      objective:"Keep access over SSH. This is an inference from the payload behavior.",
      nodes:{i:["Exposed Docker API","Reported entry"],p:["Daemon creates container","Reported runtime action"],
        q:["Persistence script","Analyzed capability"],a:["Authorized key rotation","Administrative comparison"],
        s:["SSH trust changes","Shared state change"]},
      edges:[["i","p"],["p","q","unresolved"],["q","s"],["a","s","alternative"]],
      edgeNote:"The dashed link marks the unresolved caller for a given write.",
      steps:[
        {title:"Start with the reported Docker entry"},
        {title:"Follow the runtime action", show:"i p", copy:"The report links Docker API access to container creation."},
        {title:"Separate entry from payload analysis", show:"q", copy:"Datadog describes payload deployment and analyzes the SSH script. The dashed link marks the unresolved identity of the exact caller for a given write."},
        {title:"Follow the change to trust", show:"s", copy:"The analyzed script changes SSH trust and configuration. A successful login is a separate outcome."},
        {title:"Compare an approved change", show:"a", phase:1, copy:"An administrator rotating a key can produce the same kind of trust change."},
        {title:"Name the necessary step", focus:"s", candidate:"s", copy:"Both modeled trust-change paths write new trust state. The changed state alone leaves actor and authorization unresolved."},
        {title:"Choose the claim", phase:2, activity:"minimum", focus:"s", copy:"Pick a claim, then try a source set. Start with the evidence you would expect to have."},
        {title:"Review the lab results", activity:"minimum", findings:true, focus:"s", copy:"Compare your selection with the smallest sets that qualified for the measured helper cohort."}
      ],
      limits:"The selected lab case changed an inert account record. The delegated cohort spans multiple fixture types and did not test SSH login.",
      apply:"Choose sources for the claim your alert makes. Check authorization against approved changes before drawing a conclusion about the actor."
    }
  ];
  const activities=["Follow an attack","Change the tradecraft","Test the detection"];
  const graphSlots={
    i:[[15,50],[50,10]], p:[[47,18],[24,34]], q:[[82,18],[24,58]],
    a:[[47,82],[76,34]], b:[[82,82],[76,58]], s:[[82,50],[50,84]]
  };
  let walkthrough=null;
  let placementOpen=false, placement;

  function updateEntry(lesson, exercise=false){
    const url=new URL(location.href);
    if(lesson){
      url.searchParams.delete("view");
      url.searchParams.set("lesson",lesson);
    }else{
      url.searchParams.delete("lesson");
      url.searchParams.set("view","studies");
    }
    if(exercise)url.searchParams.set("exercise","placement");
    else url.searchParams.delete("exercise");
    history.replaceState(history.state,"",url);
  }
  function selectLesson(id,updateUrl=false){
    if(updateUrl)updateEntry(id);
    placementOpen=false;
    walkthrough={lesson:lessons.find(item=>item.id===id),index:0,hint:false,php:"",
      cutoff:250,lenses:"PWKDAH",observer:"",claim:"",minimumLenses:"P"};
    render();
  }
  function goToStep(index){
    Object.assign(walkthrough,{index,hint:false});
    renderWalkthrough();
    const title=$("walk-step-title");
    title.focus({preventScroll:true});
    const objective=title.closest(".lesson-panel").querySelector(".walk-objective");
    const goal=objective.getBoundingClientRect();
    title.style.scrollMarginTop=(goal.height+parseFloat(getComputedStyle(objective).top)+12)+"px";
    title.scrollIntoView({block:"nearest"});
  }
  function openPlacement(){
    if(!placement){
      const baseline=reset("php");
      const {study,metrics}=view(baseline);
      const cases=Object.fromEntries([["child","Child process"],["worker","In-process worker"],["admin","Approved read"]].map(([id,label])=>{
        const {assessment}=view(change(baseline,{case:id}));
        const verdicts=Object.fromEntries(["operation","effect","attribution","authorization"].map(key=>[key,claimValue(assessment,key)[0]]));
        return [id,{label,verdicts}];
      }));
      placement=initializePlacement($("php-placement"),{
        revision:study.revision,confirmed:metrics.effect[0],eligible:metrics.effect[1],cases
      },()=>{
        placementOpen=false;
        updateEntry(walkthrough.lesson.id);
        renderWalkthrough();
        $("walk-placement").focus();
      });
    }
    placementOpen=true;
    updateEntry(walkthrough.lesson.id,true);
    renderWalkthrough();
    placement.open();
  }
  function lessonTabs(){
    const tabs=$("lesson-tabs");
    for(const l of lessons){
      const tab=node("button","",l.label);
      tab.type="button"; tab.id="lesson-tab-"+l.id;
      tab.dataset.lesson=l.id;
      tab.setAttribute("role","tab");
      tab.setAttribute("aria-controls","lesson-panel");
      tab.addEventListener("click",()=>selectLesson(l.id,true));
      tabs.append(tab);
    }
    tabs.addEventListener("keydown",event=>{
      if(!["ArrowRight","ArrowLeft","Home","End"].includes(event.key)||!event.target.matches('[role="tab"]'))return;
      event.preventDefault();
      const at=lessons.findIndex(item=>item.id===event.target.dataset.lesson);
      const ix=event.key==="Home"?0:event.key==="End"?lessons.length-1:
        (at+(event.key==="ArrowRight"?1:-1)+lessons.length)%lessons.length;
      selectLesson(lessons[ix].id,true);
      $("lesson-tab-"+lessons[ix].id).focus();
    });
    $("free-explore").addEventListener("click",()=>openStudy());
    $("walk-placement").addEventListener("click",openPlacement);
    $("walk-back").addEventListener("click",()=>goToStep(walkthrough.index-1));
    $("walk-next").addEventListener("click",()=>goToStep(walkthrough.index+1));
    $("walk-skip").addEventListener("click",()=>goToStep(walkthrough.lesson.steps.length-1));
    $("walk-replay").addEventListener("click",()=>{
      selectLesson(walkthrough.lesson.id);
      goToStep(0);
    });
    $("walk-hint").addEventListener("click",()=>{
      walkthrough.hint=!walkthrough.hint;
      renderWalkthrough();
    });
  }
  function openStudy(patch){
    if(patch)state=change(reset(patch.study),patch);
    walkthrough=null;
    placementOpen=false;
    updateEntry();
    render();
    $("study").focus();
  }
  function renderWalkGraph(lesson,step,known,candidate){
    const map=$("walk-map");
    const coordinates=(slot,size)=>size===1&&lesson.narrowSlots?.[slot]||graphSlots[slot][size];
    if(map.dataset.lesson!==lesson.id){
      map.dataset.lesson=lesson.id;
      map.replaceChildren();
      for(const [size,cls] of ["wide","narrow"].entries()){
        const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");
        svg.setAttribute("viewBox","0 0 100 100");
        svg.setAttribute("preserveAspectRatio","none");
        svg.setAttribute("class","walk-lines "+cls);
        svg.setAttribute("aria-hidden","true");
        for(const [from,to,kind="primary"] of lesson.edges){
          const line=document.createElementNS(svg.namespaceURI,"line");
          const [x,y]=coordinates(from,size), [tx,ty]=coordinates(to,size);
          for(const [key,value] of Object.entries({x1:x,y1:y,x2:tx,y2:ty}))line.setAttribute(key,value);
          Object.assign(line.dataset,{from,to,kind});
          svg.append(line);
        }
        map.append(svg);
      }
      for(const [slot,[title,role]] of Object.entries(lesson.nodes)){
        const tile=node("div","walk-node");
        tile.dataset.slot=slot;
        const [x,y]=coordinates(slot,0), [mx,my]=coordinates(slot,1);
        for(const [key,value] of Object.entries({x,y,mx,my}))tile.style.setProperty("--walk-"+key,value+"%");
        tile.append(node("strong","",title),node("span","walk-role",role),node("span","walk-candidate","Candidate chokepoint"));
        map.append(tile);
      }
    }
    const focus=(step.focus||step.show||"").split(" ");
    const sensors=step.activity==="php" ? {process:["p","q"],file:["s"],policy:[]}[walkthrough.php]
      : step.activity==="observation" ? {kernel:["p"],files:["a"],outcome:["b"]}[walkthrough.observer] : [];
    const observed=sensors||[];
    const compare=lesson.id==="convergence"&&known.has("a")&&known.has("s");
    for(const tile of map.querySelectorAll("[data-slot]")){
      const slot=tile.dataset.slot;
      tile.hidden=!known.has(slot);
      tile.classList.toggle("current",focus.includes(slot));
      tile.classList.toggle("candidate",candidate.includes(slot));
      tile.classList.toggle("sensor-focus",observed.includes(slot));
    }
    for(const line of map.querySelectorAll("line")){
      const {from,to}=line.dataset;
      line.style.visibility=known.has(from)&&known.has(to)?"visible":"hidden";
      line.classList.toggle("current",focus.includes(to)||compare&&to==="s");
    }
    const unbound=lesson.edges.some(([from,to,kind])=>kind==="unresolved"&&known.has(from)&&known.has(to));
    $("walk-map-key").hidden=!observed.length&&!unbound;
    $("walk-map-key").textContent=unbound?lesson.edgeNote:"The dashed outline marks the selected observation point.";
    $("walk-relationships").replaceChildren(...lesson.edges.filter(([from,to])=>known.has(from)&&known.has(to))
      .map(([from,to,kind])=>node("li","",lesson.nodes[from][0]+" to "+lesson.nodes[to][0]+
        (kind==="unresolved"?" · Exact causal link unresolved":kind==="alternative"?" · Alternative or administrative comparison":" · Modeled relationship"))));
  }

  function choiceButtons(title,key,options){
    const group=node("div","walk-choice");
    group.setAttribute("role","group");
    group.setAttribute("aria-label",title);
    group.append(node("strong","",title));
    for(const [value,label] of options){
      const b=node("button","",label);
      b.type="button";
      b.dataset.focus="walk-"+key+"-"+value;
      b.setAttribute("aria-pressed",String(walkthrough[key]===value));
      b.addEventListener("click",()=>{
        walkthrough[key]=value;
        renderWalkthrough();
      });
      group.append(b);
    }
    return group;
  }
  function claimRow(study,assessment,key,cohort){
    const [verdict,refs,missing]=claimValue(assessment,key);
    const item=node("div","walk-claim");
    const title=node("div","walk-claim-title");
    const badge=node("span","tag state",states[verdict]);
    badge.dataset.v=verdict;
    title.append(node("strong","",claimLabel(study,key,cohort)),badge);
    item.append(title);
    if(refs.length||missing.length){
      const details=node("details");
      details.append(node("summary","","Evidence and gaps"));
      if(refs.length){
        const list=node("ul");
        for(const id of refs)list.append(node("li","",id+" · "+study.evidence[id]));
        details.append(list);
      }
      if(missing.length){
        const list=node("ul");
        for(const gap of missing)list.append(node("li","",missingLabels[gap]||gap));
        details.append(list);
      }
      item.append(details);
    }
    return item;
  }
  function studyLink(label,patch){
    const b=node("button","",label);
    b.type="button";
    b.addEventListener("click",()=>openStudy(patch));
    return b;
  }
  function diagnosticTable(d){
    const table=node("table","diagram-table");
    const header=table.createTHead().insertRow();
    for(const label of ["Call variant","Reference trace","Runtime hook"]){
      const cell=node("th","",label);cell.scope="col";header.append(cell);
    }
    const body=table.createTBody();
    for(const [i,label] of d.labels.entries()){
      const row=body.insertRow();
      for(const value of [label,d.reference[i]+" / "+d.denominator,d.observed[i]+" / "+d.denominator])
        row.insertCell().textContent=value;
    }
    return table;
  }
  function evidencePanel(activity,findings){
    const {php,cutoff,lenses,observer,claim,minimumLenses}=walkthrough;
    const controls=$("walk-evidence-controls"), proof=$("walk-proof"), results=$("walk-results");
    controls.replaceChildren();proof.replaceChildren();results.replaceChildren();
    const notes={
      process:"Process lineage can tie the child to the PHP worker. The in-process route has no child to observe.",
      file:"A completed read tied to the designated file speaks to either route. Check the exact file and actor.",
      policy:"The applicable policy distinguishes the same read on an approved route from a prohibited read.",
      kernel:"A module-load record can serve as a lead on the kernel route. A canary write test cannot measure module-load coverage.",
      files:"File integrity can show a persisted replacement. A matching write record can identify the operation when the collector captures it.",
      outcome:"Compare independent views of process state to investigate concealment. The canary diagnostic measures writes and does not measure concealment."
    };
    if(activity==="php"){
      controls.append(choiceButtons("Pick a record to inspect","php",[["process","Process lineage"],["file","File read"],["policy","Authorization"]]));
      if(php)proof.append(node("p","",notes[php]));
      if(!findings)return;
      const {study,metrics}=view(reset("php"));
      results.append(node("p","walk-result-line",metrics.effect[0]+" / "+metrics.effect[1]+" prohibited canary reads confirmed · Measured"));
      for(const [id,label] of [["child","Child process"],["worker","In-process worker"],["admin","Approved read"]]){
        const {assessment}=view(change(reset("php"),{case:id}));
        const entry=node("section","walk-claim");
        entry.append(node("strong","",label),node("div","",[
          "Read "+states[claimValue(assessment,"effect")[0]],"Authorization violation "+states[claimValue(assessment,"authorization")[0]]
        ].join(" · ")));
        results.append(entry);
      }
      results.append(studyLink("Explore the PHP study",{study:study.id,case:"child"}));
    }
    if(activity==="resilience"){
      controls.append(choiceButtons("Receipt cutoff","cutoff",[[250,"250 ms"],[null,"Final replay"]]));
      const patch={...helperCase,cutoff,lenses};
      const {study,assessment}=view(change(reset(patch.study),patch));
      const effectOnly=study.groups.find(g=>g.profile==="augmented"&&g.cutoff===null).minimum[patch.cohort].effect[0];
      controls.append(choiceButtons("Replay evidence","lenses",[[study.lenses,"All lenses"],[effectOnly,"Keep only effect evidence"]]));
      proof.append(node("p","", "Measured helper case · Native and supplemental evidence"));
      for(const key of ["effect","boundary","causal"])proof.append(claimRow(study,assessment,key,patch.cohort));
      proof.append(node("p","","Coverage limited means the selected evidence cannot establish the claim."));
      if(findings){
        const rows=[
          ["250 ms, all lenses",{cutoff:250,lenses:study.lenses}],
          ["Final replay, all lenses",{cutoff:null,lenses:study.lenses}],
          ["Final replay, effect evidence only",{cutoff:null,lenses:effectOnly}]
        ];
        for(const [label,settings] of rows){
          const current=view(change(reset(patch.study),{...patch,...settings})).assessment;
          const row=node("div","walk-claim");
          row.append(node("strong","",label),node("p","","Effect "+states[claimValue(current,"effect")[0]]+
            " · Causal link "+states[claimValue(current,"causal")[0]]));
          results.append(row);
        }
        results.append(studyLink("Explore this replay",patch));
      }
    }
    if(activity==="observation"){
      controls.append(choiceButtons("Observation point","observer",[
        ["kernel","Module load"],["files","File changes"],["outcome","Process listing"]
      ]));
      if(observer)proof.append(node("p","",notes[observer]));
      if(!findings)return;
      const {study}=view(reset("gate-c2"));
      results.append(node("p","walk-result-line","Measured diagnostic · Two runs per observer and variant"),diagnosticTable(study.diagnostic),
        node("p","","The selected Tetragon hook captured the scalar and positional controls. Reference tracing confirmed completion for both vectored variants in separate runs."),
        studyLink("Explore the measured diagnostic",choices.gap),
        studyLink("Explore the synthetic A/B comparison",{...choices.arms,arm:"B"}));
    }
    if(activity==="minimum"){
      controls.append(choiceButtons("Security claim","claim",[["effect","Confirm the effect"],["causal","Link it to the earlier action"]]));
      const patch={...helperCase,cutoff:null,lenses:minimumLenses,claim:claim||"effect",selected:claim||"effect"};
      const {study,g,metrics,assessment}=view(change(reset(patch.study),patch));
      if(claim){
        const group=node("div","walk-choice");
        group.setAttribute("role","group"); group.setAttribute("aria-label","Evidence lenses");
        group.append(node("strong","","Evidence lenses"));
        for(const key of study.lenses){
          const enabled=minimumLenses.includes(key);
          const b=node("button","",key+" · "+model.lenses[key][0]);
          b.type="button";b.setAttribute("aria-pressed",String(enabled));b.dataset.focus="walk-lens-"+key;
          b.addEventListener("click",()=>{
            walkthrough.minimumLenses=enabled?minimumLenses.replace(key,""):order(study,minimumLenses+key);
            renderWalkthrough();
          });
          group.append(b);
        }
        controls.append(group);
        const count=metrics[patch.claim];
        const label=patch.claim==="causal"?"links confirmed":"effects confirmed";
        proof.append(node("p","walk-result-line",count[0]+" / "+count[1]+" "+label+" · Selected evidence"),
          claimRow(study,assessment,patch.claim,patch.cohort));
      }
      if(!findings)return;
      results.append(node("p","walk-result-line","Measured helper cohort · Final replay · Native and supplemental evidence"));
      for(const key of ["effect","causal"]){
        const masks=g.minimum[patch.cohort][key];
        for(const mask of masks){
          const report=g.rows[mask][0][patch.cohort];
          const line=node("div","walk-claim");
          line.append(node("strong","",claimLabel(study,key)+" minimum · "+shortMask(mask)),
            node("p","",report.effect[0]+" / "+report.effect[1]+" effects · "+
              report.causal[0]+" / "+report.causal[1]+" causal links"),
            studyLink("Explore "+claimLabel(study,key).toLowerCase(),{...patch,lenses:mask,claim:key,selected:key}));
          results.append(line);
        }
      }
    }
  }
  function renderWalkthrough(){
    const panel=$("lesson-panel");
    const lesson=walkthrough?.lesson;
    const retained=document.activeElement?.dataset.focus;
    $("free-explore").hidden=!lesson;
    $("lesson-heading").textContent=lesson?"Guided lessons":"Explore studies";
    for(const [i,l] of lessons.entries()){
      const tab=$("lesson-tab-"+l.id);
      tab.setAttribute("aria-selected",String(l===lesson));
      tab.tabIndex=(lesson?l===lesson:i===0)?0:-1;
    }
    panel.hidden=!lesson;
    $("lens-lab").hidden=Boolean(lesson);
    $("walk-lesson-content").hidden=placementOpen;
    $("php-placement").hidden=!placementOpen;
    if(!lesson||placementOpen)return;
    const {index,hint}=walkthrough, step=lesson.steps[index], last=lesson.steps.length-1;
    $("walk-placement").hidden=lesson.id!=="convergence"||index!==4;
    const revealed=lesson.steps.slice(0,index+1);
    const known=new Set(revealed.flatMap(item=>(item.show||"").split(" ").filter(Boolean)));
    const phase=revealed.findLast(item=>item.phase)?.phase||0;
    panel.setAttribute("aria-labelledby","lesson-tab-"+lesson.id);
    $("lesson-threat-title").textContent=lesson.heading;
    $("walk-objective-label").textContent=lesson.objectiveLabel||"Objective";
    $("lesson-objective").textContent=lesson.objective;
    $("lesson-threat").textContent=lesson.threat;
    $("lesson-source").textContent=lesson.source[0];
    $("lesson-source").href=lesson.source[1];
    $("lesson-threat").hidden=index!==0;
    $("walk-map-section").hidden=!known.size;
    const candidate=(revealed.findLast(item=>item.candidate)?.candidate||"").split(" ");
    renderWalkGraph(lesson,step,known,candidate);
    $("walk-progress").textContent=activities[phase]+" · Step "+(index+1)+" of "+(last+1);
    $("walk-step-title").textContent=step.title;
    $("walk-copy").textContent=step.copy||"Continue to reveal the first interaction.";
    const catalog=$("lesson-catalog");
    catalog.hidden=!step.catalog;
    if(step.catalog){
      catalog.href=root.dataset.catalogRoot+lesson.catalog[0]+"/";
      catalog.textContent=lesson.catalog[1];
    }
    $("walk-hint").hidden=!step.hint;
    $("walk-hint").setAttribute("aria-expanded",String(hint));
    $("walk-hint").textContent=hint?"Hide explanation":"Show explanation";
    $("walk-answer").hidden=!step.hint||!hint;
    $("walk-answer").textContent=step.hint||"";
    $("walk-evidence").hidden=!step.activity;
    $("walk-findings").hidden=!step.findings;
    $("walk-limits").textContent=lesson.limits;
    $("walk-application").textContent=lesson.apply;
    if(step.activity)evidencePanel(step.activity,step.findings);
    $("walk-back").disabled=index===0;
    $("walk-next").hidden=index===last;
    $("walk-skip").hidden=index===last;
    if(retained)panel.querySelector(`[data-focus="${CSS.escape(retained)}"]`)?.focus({preventScroll:true});
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
      b.dataset.focus="study-"+s.id;b.setAttribute("aria-pressed",String(s.id===state.study));b.addEventListener("click",()=>openStudy({study:s.id}));
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
    renderWalkthrough();
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
    openStudy(choice);
  }));
  lessonTabs();
  const entry=new URLSearchParams(location.search);
  if(entry.get("view")==="studies"){
    render();
  }else{
    const requested=lessons.find(lesson=>lesson.id===entry.get("lesson"));
    selectLesson((requested || lessons[0]).id);
  }

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
  if(walkthrough?.lesson.id==="convergence"&&entry.get("exercise")==="placement"){
    walkthrough.index=4;
    openPlacement();
  }
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
