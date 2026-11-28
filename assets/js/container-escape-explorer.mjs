export function studyProfile(graph) {
  const entries = graph.objectives.map((item) => [item.id, {
    title: item.name, objective: item.objective, target: item.requiredEffectFields[1],
    refs: item.routes[0].sources, limit: item.modelLimit, alternatives: item.otherExplanations,
    steps: item.walkthrough.map(({title,prompt})=>[title,prompt]),
    focus: item.walkthrough.map(({suggestedRoute})=>suggestedRoute),
    facts: item.optionalFacts.map(({id,label,description})=>[id,label,description]),
    defaults: item.defaultFacts,
    routes: item.routes.map((route)=>({
      id: route.id, title: route.name, level: route.revealStage,
      nodes: route.requiredBehavioralStages, detect: route.possibleDetectionPlacements,
      block: route.eligiblePreventionControlsAny, requires: route.requiredFactsAll,
      binding: route.exactBindingRequirement, refs: route.sources,
      hyp: route.provenance === 'hypothetical route',
    })),
  }]);
  return Object.fromEntries(entries);
}

export function availableRoutes(lesson, level, facts) {
  return lesson.routes.filter(item => item.level <= level &&
    (item.requires || []).every(fact => facts.has(fact)));
}
export function minimumCuts(routes, ineligible) {
  if (routes.length === 0) return [];
  const possible = [...new Set(routes.flatMap(item => item.block))]
    .filter(id => !ineligible.has(id));
  if (routes.some(item => !item.block.some(id => possible.includes(id)))) return [];
  const cuts = [];
  let smallest = possible.length + 1;
  for (let mask = 1; mask < 2 ** possible.length; mask += 1) {
    const set = possible.filter((id, ix) => mask & (1 << ix));
    if (set.length > smallest || !routes.every(item => item.block.some(id => set.includes(id)))) continue;
    if (set.length < smallest) {
      smallest = set.length;
      cuts.length = 0;
    }
    cuts.push(set);
  }
  return cuts;
}
function sharedInteractions(routes) {
  if (routes.length === 0) return [];
  return routes[0].nodes.slice(1,-1).filter(node =>
    routes.every(item => item.nodes.slice(1,-1).includes(node)));
}
function evidenceVerdicts(required, observations, authorization) {
  const effect = observations.has('outcome') && observations.has(required);
  const origin = observations.has('origin');
  const cause = effect && origin && observations.has('binding');
  return {effect,origin,cause,authorization:cause ? authorization : 'unknown'};
}
function mountExplorer(root, graph) {
  const profile = studyProfile(graph);
  const sources = Object.fromEntries(Object.entries(graph.sourceReferences)
    .map(([id,{locator,url}])=>[id,[locator,url]]));
  const controls = Object.fromEntries(Object.entries(graph.preventionControls)
    .map(([id,{name,eligibility}])=>[id,[name,eligibility]]));
  const signals = graph.detectionPlacements;
  const evidence = graph.evidenceFields;
  const byId = id => root.querySelector('#'+id);
  const ids = Object.keys(profile);
  const params = new URLSearchParams(location.search);
  const requested = params.get('objective');
  const initialKey = ids.includes(requested) ? requested : 'data';
  let state;
  function reset(key) {
    state = { key,step:0,explore:false,route:profile[key].focus[0],mode:'detect',
      facts:new Set(profile[key].defaults), selected:new Set(), blocked:new Set(),
      ineligible:new Set(), observations:new Set(), authorization:'unknown' };
  }
  reset(initialKey);
  const requestedRoute = params.get('route');
  if (profile[initialKey].routes.some((item) => item.id === requestedRoute)) {
    state.explore = true;
    state.route = requestedRoute;
  }
  function sourceLinks(keys) {
    return keys.map(id => {
      const [label,url] = sources[id];
      return '<a href="'+url+'">'+label.replaceAll('&','&amp;')+'</a>';
    }).join(' · ');
  }
  function check(kind, id, label, description, checked, disabled=false) {
    const name = kind+'-'+id;
    return '<label class="check" for="'+name+'"><input type="checkbox" id="'+name+
      '" data-kind="'+kind+'" data-id="'+id+'"'+(checked?' checked':'')+
      (disabled?' disabled':'')+'><span>'+label+
      (description?'<small>'+description+'</small>':'')+'</span></label>';
  }
  function availability() {
    const lesson = profile[state.key];
    const level = state.explore ? lesson.steps.length : state.step + 1;
    return {lesson,level,routes:availableRoutes(lesson,level,state.facts)};
  }
  function setRoute(id) {
    if (state.route !== id) {
      state.route = id;
      state.observations.clear();
      state.authorization='unknown';
    }
  }
  function renderGraph(lesson, level, routes) {
    byId('facts').innerHTML = level === lesson.steps.length ? lesson.facts.map(
      ([id,label,description]) => check('facts',id,label,description,state.facts.has(id))
    ).join('') : '';
    const active = new Set(routes.map(item => item.id));
    byId('graph').innerHTML = lesson.routes.filter(item => item.level <= level).map(item => {
      const visible = active.has(item.id);
      const label = item.hyp ? 'Hypothetical route' : 'Source-supported mechanism';
      const hit = visible && item.detect.some(id => state.selected.has(id));
      const blocked = visible && item.block.some(id => state.blocked.has(id) && !state.ineligible.has(id));
      const status = !visible ? 'Prerequisites incomplete' : state.mode === 'prevent' ?
        (blocked?'Blocked in this model':'Still reachable in this model') : state.mode === 'detect' ?
        (hit?'Touches a selected placement':'No selected placement on this route') : '';
      const statusClass = state.mode === 'prevent' && blocked ? ' blocked' : state.mode === 'detect' && hit ? ' hit' : '';
      return '<article class="route'+(item.id===state.route?' current':'')+'" data-route-row="'+item.id+'">'+
        '<div class="route-head"><h3>'+item.title+'</h3><span class="tag '+(item.hyp?'hyp':'source')+'">'+label+'</span></div>'+
        '<ol class="flow" aria-label="Required interactions">'+item.nodes.map(node=>'<li><span class="node">'+node+'</span></li>').join('')+'</ol>'+
        (status?'<p class="status compact'+statusClass+'">'+status+'</p>':'')+
        '<div class="route-head"><button type="button" id="route-'+item.id+'" data-route="'+item.id+
        '" aria-label="Inspect route for '+item.title+'" aria-pressed="'+(item.id===state.route)+'"'+(!visible?' disabled':'')+'>Inspect route</button></div></article>';
    }).join('');
    byId('alternatives').innerHTML = '<details id="alternate-origins"><summary>Other ways to see this result</summary><p>'+
      lesson.alternatives+'</p></details>';
  }
  function renderDetect(routes) {
    const possible = Object.keys(signals).filter(id => routes.some(item => item.detect.includes(id)));
    const hits = routes.filter(item => item.detect.some(id => state.selected.has(id))).length;
    return '<p class="readout" id="detect-count" aria-live="polite">'+hits+' of '+routes.length+
      ' enabled routes touch a selected placement.</p><div class="checks">'+possible.map(id =>
      check('selected',id,signals[id],'',state.selected.has(id))).join('')+
      '</div><p class="quiet">A placement indicates where you could look. It does not establish capture, a verdict, or a causal link.</p>';
  }
  function renderEvidence(lesson, item) {
    if (!item) return '<p>Enable a route before checking evidence.</p>';
    const result = evidenceVerdicts(lesson.target,state.observations,state.authorization);
    const objectiveWitness = state.key === 'data' ? 'The recipient actually received the material.' :
      state.key === 'execution' ? 'A trusted witness observed the qualifying execution.' :
      'The server resolved the key as eligible for the account and connection.';
    const outcome = [
      ['outcome',objectiveWitness], [lesson.target,'Scope required for this objective.'],
      ['origin','Bind the exact principal or workload episode.'], ['binding',item.binding]
    ];
    const row = (label, ok, success, failure) => '<div><strong>'+label+'</strong> <span class="'+
      (ok?'good':'limited')+'">'+(ok?success:failure)+'</span></div>';
    let summary = row('Objective effect',result.effect,'Supported in this example.','Evidence incomplete.');
    summary += row('Origin in view',result.origin,'Scoped origin recorded.','Origin unresolved.');
    summary += row('Causal attribution',result.cause,'Exact link supports attribution.','Effect and origin are not yet bound.');
    summary += row('Authorization at the effect',result.authorization!=='unknown',
      result.authorization==='allowed'?'Approved operation.':'Outside intended policy.','Unresolved for the linked effect.');
    return '<p><strong>'+item.title+'</strong></p><p class="quiet">Assume these exact records are available. Turn them on to see what you can conclude.</p>'+
      '<div class="checks">'+outcome.map(([id,detail])=>check('observations',id,evidence[id],detail,state.observations.has(id))).join('')+
      '</div><label for="authorization">Applicable intended policy </label>'+
      '<select id="authorization" aria-label="Applicable intended policy"><option value="unknown">Unknown</option>'+
      '<option value="allowed"'+(state.authorization==='allowed'?' selected':'')+'>Approved</option>'+
      '<option value="denied"'+(state.authorization==='denied'?' selected':'')+'>Outside policy</option></select>'+
      '<div class="split" id="evidence-verdict" aria-live="polite">'+summary+'</div>';
  }
  function renderPrevent(lesson, routes) {
    const candidates = [...new Set(routes.flatMap(item => item.block))];
    const cuts = minimumCuts(routes,state.ineligible);
    const reach = routes.filter(item => !item.block.some(id => state.blocked.has(id) && !state.ineligible.has(id))).length;
    const shared = sharedInteractions(routes);
    return '<p class="readout" id="prevent-count" aria-live="polite">'+reach+' of '+routes.length+' enabled routes remain reachable.</p>'+
      '<p class="quiet">'+lesson.limit+'</p>'+
      '<div id="min-cut"><strong>'+(!cuts.length?'No eligible cut for these routes.':'Smallest eligible cuts use '+cuts[0].length+
      (cuts[0].length===1?' control.':' controls.'))+'</strong>'+
      (cuts.length?'<ul>'+cuts.map(cut=>'<li>'+cut.map(id=>controls[id][0]).join(' + ')+'</li>').join('')+'</ul>':'')+'</div>'+
      '<p class="quiet">Shared intermediate interaction: '+(shared.length?shared.join(' · '):'none across these routes')+'.</p>'+
      '<div class="checks">'+candidates.map(id=>check('blocked',id,controls[id][0],controls[id][1],
        state.blocked.has(id),state.ineligible.has(id))).join('')+'</div>'+
      '<details id="eligibility"><summary>Control eligibility assumptions</summary><p class="quiet">Mark a control unavailable when you cannot verify its enforcement for the named routes.</p>'+
      '<div class="checks">'+candidates.map(id=>check('ineligible',id,'Unavailable · '+controls[id][0],'',
        state.ineligible.has(id))).join('')+'</div></details>';
  }

  function render() {
    const focus = document.activeElement?.id;
    const opened = [...root.querySelectorAll('details[open]')].map(item=>item.id);
    const {lesson,level,routes} = availability();
    const selected = lesson.routes.find(item=>item.id===state.route);
    const inactive = selected && state.explore && !routes.includes(selected) ? selected : undefined;
    const item = inactive ? undefined : routes.find(item=>item.id===state.route) || routes[0];
    if (item) setRoute(item.id);
    byId('tabs').innerHTML = ids.map(id=>{
      const active = id===state.key;
      return '<button type="button" role="tab" id="tab-'+id+'" data-objective="'+id+
        '" aria-controls="lesson" aria-selected="'+active+'" tabindex="'+(active?'0':'-1')+'">'+profile[id].title+'</button>';
    }).join('');
    byId('lesson').setAttribute('aria-labelledby','tab-'+state.key);
    byId('lesson-title').textContent = lesson.title;
    byId('objective').textContent = lesson.objective;
    byId('progress').textContent = state.explore ? 'All modeled routes' : 'Step '+(state.step+1)+' of '+lesson.steps.length;
    byId('step-title').textContent = state.explore ? 'Compare the routes' : lesson.steps[state.step][0];
    byId('step-copy').textContent = state.explore ? 'Select an interaction to investigate. Change which assumptions hold and compare the result.' : lesson.steps[state.step][1];
    byId('sources').innerHTML = sourceLinks(lesson.refs);
    byId('explore').setAttribute('aria-pressed',String(state.explore));
    byId('explore').textContent = state.explore ? 'Return to walkthrough' : 'Explore all routes';
    byId('back').disabled = state.explore || state.step===0;
    byId('next').disabled = state.explore || state.step===lesson.steps.length-1;
    renderGraph(lesson,level,routes);
    for (const button of byId('mode-buttons').querySelectorAll('button')) {
      button.setAttribute('aria-pressed',String(button.dataset.mode===state.mode));
    }
    let analysis;
    if (state.mode==='detect') analysis = renderDetect(routes);
    if (state.mode==='evidence') analysis = renderEvidence(lesson,item);
    if (state.mode==='prevent') analysis = renderPrevent(lesson,routes);
    if (inactive) {
      const prerequisites = lesson.facts.filter(([id]) => inactive.requires.includes(id))
        .map(([, label]) => label);
      analysis = '<p class="status"><strong>'+inactive.title+'</strong> needs these prerequisites enabled: '+
        prerequisites.join(' · ')+'</p>'+analysis;
    }
    const referenced = item || inactive;
    if (referenced) analysis += '<div class="split compact"><strong>Selected route sources</strong><p>'+sourceLinks(referenced.refs)+'</p></div>';
    byId('analysis').innerHTML = analysis;
    for (const id of opened) {
      if (byId(id)) byId(id).open = true;
    }
    if (focus && byId(focus) && !byId(focus).disabled && document.activeElement!==byId(focus)) {
      byId(focus).focus({preventScroll:true});
    }
  }
  function navigateLesson(id) {
    reset(id);
    const url = new URL(location.href);
    url.searchParams.set('objective',id);
    url.searchParams.delete('route');
    try { history.replaceState(null,'',url); } catch {}
    render();
    byId('tab-'+id).focus({preventScroll:true});
  }
  function go(delta) {
    const lesson = profile[state.key];
    state.step += delta;
    setRoute(lesson.focus[state.step]);
    state.mode = state.step === lesson.steps.length-1 ? 'prevent' : state.step>0 ? 'evidence' : 'detect';
    render();
    byId('step-title').focus();
  }
  byId('tabs').addEventListener('click',event=>{
    const id = event.target.closest('[data-objective]')?.dataset.objective;
    if (id) navigateLesson(id);
  });
  byId('tabs').addEventListener('keydown',event=>{
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const at = ids.indexOf(state.key);
    const index = event.key==='Home' ? 0 : event.key==='End' ? ids.length-1 :
      (at + (event.key==='ArrowRight'?1:-1) + ids.length) % ids.length;
    navigateLesson(ids[index]);
  });
  byId('back').addEventListener('click',()=>go(-1));
  byId('next').addEventListener('click',()=>go(1));
  byId('replay').addEventListener('click',()=>{
    reset(state.key);
    render();
    byId('step-title').focus();
  });
  byId('explore').addEventListener('click',()=>{
    state.explore = !state.explore;
    render();
  });
  byId('graph').addEventListener('click',event=>{
    const route = event.target.closest('[data-route]')?.dataset.route;
    if (route) { setRoute(route); render(); }
  });
  byId('mode-buttons').addEventListener('click',event=>{
    const mode = event.target.closest('[data-mode]')?.dataset.mode;
    if (mode) { state.mode=mode; render(); }
  });
  root.addEventListener('change',event=>{
    const target = event.target;
    if (target.id==='authorization') state.authorization = target.value;
    else {
      const {kind,id} = target.dataset;
      if (!kind) return;
      if (target.checked) state[kind].add(id);
      else state[kind].delete(id);
      if (kind==='ineligible' && target.checked) state.blocked.delete(id);
    }
    render();
  });
  const lab = [
    ['Gate B','Synthetic','4/4 primary positive canary writes. Direct writes needed workload, kernel, and outcome evidence. Delegated writes needed workload, delegation, and outcome evidence.',root.dataset.studies],
    ['Gate C','Measured','8/8 primary delegated and 0/8 primary direct effects with full instrumentation. Two delayed positives are outside the primary counts. The test used a fixed canary and helper.',root.dataset.studies],
    ['Gate C.2','Measured','24/39 downstream effects and 7/14 causal links in final augmented replay. The study used inert records and a fake read marker. Each claim has its own denominator.',root.dataset.studies],
    ['Gate C.3','Synthetic','10/16 downstream effects in the original observation model and 16/16 with the complementary observer. The replay used modeled observations.',root.dataset.studies]
  ];
  byId('studies').innerHTML = '<div class="evidence-cards">'+lab.map(([name,kind,description,url])=>
    '<article><h3>'+name+' <span class="tag '+(kind==='Measured'?'measure':'synthetic')+'">'+kind+
    '</span></h3><p>'+description+'</p><a href="'+url+'">'+name+' study summary</a></article>').join('')+
    '</div><p class="quiet">The studies test canary evidence. The route and prevention exercises use hypothetical models with their own assumptions.</p>';
  render();
}

async function initializeExplorer(root) {
  const status = root.querySelector('#container-explorer-status');
  try {
    const response = await fetch(root.dataset.graph);
    if (!response.ok) throw new Error('Graph unavailable');
    const graph = await response.json();
    if (graph.format !== 'container-escape-research-review/v1' || !graph.objectives?.length)
      throw new Error('Unsupported graph');
    mountExplorer(root, graph);
    root.querySelector('#container-explorer-content').hidden = false;
    status.hidden = true;
  } catch {
    status.textContent = 'The walkthrough is unavailable. The research study still explains the evidence and routes.';
  }
}

if (typeof document !== 'undefined') {
  const root = document.querySelector('[data-container-explorer]');
  if (root) initializeExplorer(root);
}
