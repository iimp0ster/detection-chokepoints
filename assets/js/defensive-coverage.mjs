export function missingEvidence(alternatives, active) {
  let nearest = null;
  for (const group of alternatives) {
    const missing = group.filter((id) => !active.has(id));
    if (nearest === null || missing.length < nearest.length) nearest = missing;
  }
  return nearest;
}

export function sitePath(path, base = '') {
  return base.replace(/\/$/, '') + path;
}

export function validProfile(data) {
  if (!data || data.schemaVersion !== '1.0.0') return false;
  const lists = [data.references, data.observationFamilies, data.collectionSources,
    data.presets, data.variations];
  if (!lists.every((items) => Array.isArray(items) && items.length)) return false;
  if (data.behavioralGraph &&
      (!/^\/assets\/data\/(?:[a-z0-9-]+\/)*[a-z0-9-]+(?:\.[a-z0-9-]+)*\.json$/.test(data.behavioralGraph.path) ||
       !/^\/lens-explorer\/[a-z0-9-]+\/$/.test(data.behavioralGraph.explorer))) return false;
  return data.references.every(({url}) => {
    try {
      const reference = new URL(url);
      return reference.protocol === 'https:' && !reference.username && !reference.password;
    } catch {
      return false;
    }
  });
}

export function approvedRoute(graph, objectiveId, routeId) {
  const objective = graph.objectives?.find((item) => item.id === objectiveId);
  return objective?.routes.find((item) => item.id === routeId);
}

function mountCoverage(root, data, graph) {
  const base = root.dataset.baseurl || '';
  const hasGraph=Boolean(graph.objectives?.length && data.behavioralGraph);
  const at = (name) => root.querySelector('#'+name);
  const h = (text) => String(text).replace(/[&<>"']/g,(char)=>({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[char]);
  const statuses = {
    source:['S','Source-supported opportunity'],
    measured:['M','Measured observation'],
    synthetic:['Y','Synthetic expectation'],
    context:['C','Supporting context'],
    unavailable:['X','Unavailable in named capture'],
    hypothesis:['?','Untested hypothesis'],
    unmapped:['·','No observation mapped']
  };
  const labels = {
    'native-projection':'Native • sanitized projection',
    supplemental:'Supplemental instrumentation',
    synthetic:'Synthetic',
    measured:'Measured', source:'Source-supported', hypothesis:'Untested hypothesis', 'source-summary':'Source summary'
  };
  const refs = new Map(data.references.map((ref)=>[ref.id,ref]));
  const families = new Map(data.observationFamilies.map((family)=>[family.id,family]));
  const sources = new Map(data.collectionSources.map((source)=>[source.id,source]));
  const defaultVariation = data.variations.find((item)=>item.id===data.initialVariation) || data.variations[0];
  const active = {
    variation:defaultVariation.id,family:data.initialObservation || defaultVariation.observations[0]?.family || families.keys().next().value,
    collection:new Set(data.presets[0]?.sources || []), preset:data.presets[0]?.id,
    objective:graph.objectives?.[0]?.id, route:graph.objectives?.[0]?.routes[0]?.id, reveal:1,
    placement:data.placements?.[0]?.id
  };
  const current = () => data.variations.find((item)=>item.id===active.variation);
  function cite(ids=[]) {
    return ids.map((id)=>{
      const ref=refs.get(id);
      return '<a href="'+h(ref.url)+'" title="'+h(ref.locator)+'">'+h(ref.title)+'</a>';
    }).join(' · ');
  }
  function tag(kind,label) {
    return '<span class="coverage-tag state-'+h(kind)+'">'+h(label)+'</span>';
  }
  function option(id,name) {
    return '<option value="'+h(id)+'">'+h(name)+'</option>';
  }
  function specs() {
    return data.variations.map((item)=>option(item.id,item.title)).join('');
  }
  function cell(variation, family) {
    return variation.observations.find((item)=>item.family===family) || {
      state:'unmapped',
      relevance:'This profile does not map this observation to the variation.',
      establishes:'The cell adds no claim about the variation.',
      limit:'A blank mapping is not evidence that the activity or signal is absent.'
    };
  }
  function displayMatrix() {
    const rows=data.variations.map((variation)=>{
      const cells=data.observationFamilies.map((family)=>{
        const state=cell(variation,family.id).state;
        const [mark,label]=statuses[state];
        const aid=variation.id+'-'+family.id;
        return '<td><button id="coverage-cell-'+h(aid)+'" type="button" data-variation="'+h(variation.id)+
         '" data-family="'+h(family.id)+'" aria-pressed="false" aria-label="'+h(mark+', '+variation.title+', '+family.label+', '+label)+'"><span class="state-'+
         h(state)+'" aria-hidden="true">'+h(mark)+'</span></button></td>';
      }).join('');
      return '<tr><th scope="row"><button type="button" data-variation="'+h(variation.id)+'" aria-pressed="false">'+
       h(variation.title)+'</button></th>'+cells+'</tr>';
    }).join('');
    at('coverage-matrix').innerHTML=
     '<div class="coverage-pair"><label>Tradecraft variation<select class="coverage-variation">'+specs()+
     '</select></label><label>Observation family<select id="coverage-family">'+
     data.observationFamilies.map((family)=>option(family.id,family.label)).join('')+
     '</select></label></div><p class="coverage-note">Select a row, column, or cell. A measurement applies only to the named study and configuration.</p>'+
     '<ul class="coverage-legend" aria-label="Observation legend">'+Object.entries(statuses).map(([state,[mark,label]])=>
       '<li>'+tag(state,mark)+' '+h(label)+'</li>').join('')+'</ul>'+
     '<div class="coverage-scroll coverage-matrix" role="region" aria-label="Tradecraft by observation family" tabindex="0">'+
     '<table><thead><tr><th scope="col">Variation</th>'+data.observationFamilies.map((family)=>
       '<th scope="col"><button type="button" data-family="'+h(family.id)+'" aria-pressed="false" aria-label="'+h(family.short+', '+family.label)+'">'+h(family.short)+'</button></th>').join('')+
     '</tr></thead><tbody>'+rows+'</tbody></table></div><div id="coverage-matrix-detail" class="coverage-readout" aria-live="polite"></div>';
  }
  function selectState() {
    root.querySelectorAll('.coverage-variation').forEach((el)=>{el.value=active.variation;});
    at('coverage-family').value=active.family;
    at('coverage-matrix').querySelectorAll('button[data-family],button[data-variation]').forEach((btn)=>{
      btn.setAttribute('aria-pressed',String((!btn.dataset.variation||btn.dataset.variation===active.variation)&&
                                             (!btn.dataset.family||btn.dataset.family===active.family)));
    });
  }
  function detail() {
    const variation=current();
    const selected=cell(variation,active.family);
    const dict=[
      ['Why it matters',selected.relevance],['What it supports',selected.establishes],['What stays open',selected.limit]
    ];
    const mapped=data.variations.filter((item)=>['source','measured','synthetic'].includes(cell(item,active.family).state));
    at('coverage-matrix-detail').innerHTML=
      '<h4>'+h(variation.title)+' · '+h(families.get(active.family).label)+'</h4>'+
      tag(selected.state,statuses[selected.state][1])+
      '<dl>'+dict.map(([term,body])=>'<dt>'+h(term)+'</dt><dd>'+h(body)+'</dd>').join('')+
      '</dl><p class="coverage-note">'+h(variation.scope)+'</p>'+
      '<p><strong>Mapped in this profile</strong> '+(mapped.length?mapped.map((item)=>{
        const entry=cell(item,active.family);
        return h(item.title)+' <span class="coverage-note">('+h(statuses[entry.state][1])+')</span>';
      }).join(' · '):'No source-backed, measured, or synthetic relationship is mapped for this family.')+
      '</p><div class="coverage-note">'+cite(variation.refs)+'</div>';
  }
  function guidanceControls() {
    at('coverage-guidance').innerHTML=
     '<div class="coverage-pair"><label>Tradecraft variation<select class="coverage-variation">'+specs()+'</select></label>'+
     '<label>Illustrative collection profile<select id="coverage-preset">'+data.presets.map((preset)=>option(preset.id,preset.label)).join('')+
     '<option value="custom">Custom selection</option></select></label></div>'+
     '<details><summary>Choose individual sources</summary>'+
     '<div class="coverage-sources">'+data.collectionSources.map((source)=>
       '<label class="coverage-check"><input type="checkbox" data-collection="'+h(source.id)+'"><span>'+h(source.label)+
       '<small>'+h(source.scope)+'</small></span></label>').join('')+
     '</div></details><div id="coverage-guidance-result" aria-live="polite"></div>';
  }
  function guidance() {
    at('coverage-preset').value=active.preset || 'custom';
    at('coverage-guidance').querySelectorAll('[data-collection]').forEach((box)=>{
      box.checked=active.collection.has(box.dataset.collection);
    });
    const variation=current();
    const signals = variation.observations.filter((item)=>{
      if (['unavailable','synthetic'].includes(item.state)) return false;
      return (families.get(item.family).collectionAny || []).some((id)=>active.collection.has(id));
    }).map((item)=>families.get(item.family).label);
    const claims=variation.claims.map((claim)=>{
      const missing=claim.availability==='unavailable'
        ? null : missingEvidence(claim.requiresAny,active.collection);
      const met=missing?.length===0;
      const st=!missing?'Unavailable in named capture':met?'Could support with the exact records':'Needs additional evidence';
      return '<article class="coverage-claim"><h4>'+h(claim.title)+'</h4>'+
        tag(!missing?'unavailable':met?'source':'context',st)+
        (missing?.length?'<p><strong>One way to close the gap</strong> '+missing.map((id)=>h(sources.get(id).label)).join(' + ')+'</p>':'')+
        '<p>'+h(claim.qualification)+'</p></article>';
    }).join('');
    at('coverage-guidance-result').innerHTML=
     '<div class="coverage-readout"><p><strong>What to look for</strong> '+(signals.length?signals.map(h).join(' · '):'No matching signal family is selected for this variation.')+'</p>'+
     '<p><strong>Useful hunt question</strong> '+h(variation.hunt)+'</p>'+
     '<p class="coverage-note">The selected sources describe record availability. Check actual fields, result, and joins before calling a finding supported.</p></div>'+
     '<div class="coverage-claims">'+claims+'</div>';
  }

  function graphControls() {
    if (!hasGraph) {
      (at('coverage-graph').closest('details,section') || at('coverage-graph')).hidden=true;
      root.querySelectorAll('.coverage-open-explorer').forEach((link)=>{link.hidden=true;});
      return;
    }
    at('coverage-graph').innerHTML=
     '<div class="coverage-pair"><label>Objective<select id="coverage-objective">'+
     graph.objectives.map((item)=>option(item.id,item.name)).join('')+
     '</select></label><label>Modeled route<select id="coverage-route"></select></label></div>'+
     '<div id="coverage-route-view" aria-live="polite"></div><div class="coverage-options"><button type="button" id="coverage-reveal">Reveal next interaction</button>'+
     '<button type="button" id="coverage-reset-path">Reset reveal</button></div>'+
     '<p class="coverage-note">The route comes from the reviewed Explorer. Changing telemetry leaves it in place. Graph position does not measure detection latency.</p>'+
     '<div id="coverage-placement"></div>'+
     '<p><a class="coverage-open-explorer" href="'+h(sitePath(data.behavioralGraph.explorer,base))+'">Open the full objective walkthrough</a></p>';
    if (data.placements?.length) {
      at('coverage-placement').innerHTML=
       '<label>Where can I act? <select id="coverage-placement-select">'+data.placements.map((p)=>option(p.id,p.title)).join('')+
       '</select></label><div class="coverage-readout" id="coverage-placement-result" aria-live="polite"></div>';
    }
  }
  function placement() {
    if (!hasGraph) return;
    const current=data.placements?.find((item)=>item.id===active.placement);
    if (!current) return;
    at('coverage-placement-select').value=current.id;
    at('coverage-placement-result').innerHTML='<h4>'+h(current.title)+'</h4><dl>'+
     ['detection','prevention','deception','investigation'].map((key)=>
      '<dt>'+h(key[0].toUpperCase()+key.slice(1))+'</dt><dd>'+h(current[key])+'</dd>').join('')+
     '</dl><p class="coverage-note">These are scoped defensive opportunities. Eligibility and telemetry are separate checks.</p>';
  }
  function routeView() {
    if (!hasGraph) return;
    const objective=graph.objectives.find((item)=>item.id===active.objective);
    const route=objective.routes.find((item)=>item.id===active.route);
    at('coverage-objective').value=active.objective;
    const routeSelector=at('coverage-route');
    if (routeSelector.dataset.objective!==active.objective) {
      routeSelector.innerHTML=objective.routes.map((item)=>option(item.id,item.name)).join('');
      routeSelector.dataset.objective=active.objective;
    }
    routeSelector.value=active.route;
    const conditions=route.requiredFactsAll.map((id)=>objective.optionalFacts.find((fact)=>fact.id===id)?.label || id);
    const detached=!current().graph;
    at('coverage-route-view').innerHTML=(detached?'<p class="coverage-note">The selected fixture example has no mapped route. The Explorer path below is separate.</p>':'')+
      '<p>'+h(objective.objective)+'</p>'+
      tag(route.provenance==='hypothetical route'?'hypothesis':'source',route.provenance)+
      '<ol class="coverage-graph" aria-label="Revealed interactions">'+route.requiredBehavioralStages.slice(0,active.reveal).map((node)=>
        '<li><span class="coverage-node">'+h(node)+'</span></li>').join('')+'</ol>'+
      '<p class="coverage-note">'+active.reveal+' of '+route.requiredBehavioralStages.length+' interactions revealed.</p>'+
      (conditions.length?'<p><strong>All route prerequisites</strong> '+conditions.map(h).join(' · ')+'</p>':'')+
      '<details><summary>Model boundary and other possible origins</summary><p>'+h(objective.modelLimit)+'</p><p>'+
      h(objective.otherExplanations)+'</p></details>';
    const reveal=at('coverage-reveal'), reset=at('coverage-reset-path');
    const focus=document.activeElement;
    reveal.disabled=active.reveal>=route.requiredBehavioralStages.length;
    reset.disabled=active.reveal<=1;
    if (focus===reveal && reveal.disabled && !reset.disabled) reset.focus({preventScroll:true});
    if (focus===reset && reset.disabled && !reveal.disabled) reveal.focus({preventScroll:true});
    root.querySelectorAll('.coverage-open-explorer').forEach((link)=>{
      const query = new URLSearchParams({objective:active.objective,route:active.route});
      link.href=sitePath(data.behavioralGraph.explorer,base)+'?'+query;
    });
  }
  function renderExamples() {
    const items=data.evidenceExamples||[];
    at('coverage-examples').hidden=!items.length;
    at('coverage-examples').innerHTML=items.length?'<h4>What the observers recorded</h4>'+items.map((item)=>{
      const fields=item.fields.map(({field,value})=>'<tr><th scope="row">'+h(field)+'</th><td>'+h(value)+'</td></tr>').join('');
      const defs=[['Identifies',item.identifies],['Establishes',item.establishes],['Leaves open',item.limits],
        ['Add to strengthen the finding',item.strengthen],['Administrative equivalent',item.administrative]];
      return '<details><summary>'+h(item.title)+' · '+h(labels[item.provenance])+'</summary>'+
       '<p class="coverage-note">'+h(item.study)+' · '+h(item.locator)+'</p>'+
       '<div class="coverage-scroll" role="region" aria-label="'+h(item.title+' fields')+'" tabindex="0">'+
       '<table class="coverage-evidence-table"><tbody>'+fields+'</tbody></table></div><div class="coverage-readout"><dl>'+
       defs.map(([k,v])=>'<dt>'+h(k)+'</dt><dd>'+h(v)+'</dd>').join('')+'</dl></div>'+
       '<p class="coverage-note">'+cite(item.refs)+'</p></details>';
    }).join(''):'';
  }
  function compare(finding, context) {
    if (!finding.comparisons?.length) return '';
    const names=[...new Set(finding.comparisons.flatMap((entry)=>entry.metrics.map((metric)=>metric.label)))];
    return '<div class="coverage-scroll" role="region" aria-label="'+h(finding.title+' '+context)+'" tabindex="0"><table>'+
     '<thead><tr><th scope="col">Evidence or writer</th>'+
     names.map((name)=>'<th scope="col">'+h(name)+'</th>').join('')+'</tr></thead><tbody>'+
     finding.comparisons.map((item)=>'<tr><th scope="row">'+h(item.label)+'</th>'+names.map((name)=>{
       const metric=item.metrics.find((entry)=>entry.label===name);
       return '<td>'+(metric?'<strong>'+metric.confirmed+'/'+metric.denominator+'</strong>':'Outside this comparison')+'</td>';
     }).join('')+'</tr>').join('')+'</tbody></table></div>';
  }
  function renderStudies() {
    const findings=data.findings||[];
    if (!findings.length && !data.evidenceExamples?.length) at('coverage-evidence').closest('details').hidden=true;
    at('coverage-quick').hidden=!findings.some((item)=>item.featured);
    function compactReadout(item) {
      if (!item.comparisons?.length || item.comparisons.length>2) return '';
      return '<div class="coverage-stat">'+item.comparisons.map((row)=>
        '<p><strong>'+h(row.label)+'</strong> '+row.metrics.map((metric)=>
          metric.confirmed+'/'+metric.denominator+' '+h(metric.label.toLowerCase())).join(' · ')+'</p>').join('')+'</div>';
    }
    at('coverage-quick').innerHTML=findings.filter((item)=>item.featured).map((item)=>
      '<article class="coverage-finding"><div class="coverage-tags">'+tag(item.provenance,labels[item.provenance])+
      ' <span class="coverage-note">'+h([item.study,item.cutoff].filter(Boolean).join(' · '))+'</span></div>'+
      '<h3>'+h(item.title)+'</h3>'+(!item.lensKey?'<p>'+h(item.lead)+'</p>':'')+
      compactReadout(item)+
      (item.lensKey?'<p class="coverage-note">'+h(item.lensKey)+'</p>':'')+
      '<a href="#coverage-finding-'+h(item.id)+'">See scope and smallest sets<span class="coverage-sr"> for '+h(item.title)+'</span></a></article>'
    ).join('');
    at('coverage-findings').hidden=!findings.length;
    at('coverage-findings').innerHTML=findings.length?'<h4>Study results and smallest qualifying sets</h4>'+
     '<p class="coverage-note">Each minimum is tied to its study, path, cutoff and claim. These are evidence sets, not prevention cuts.</p>'+
     findings.map((item)=>{
       const minima=(item.minima||[]).map((minimum)=>
        '<li><strong>'+h(minimum.lenses.join('/'))+'</strong> · '+h(minimum.path+' · '+minimum.claim)+'. '+h(minimum.scope)+'</li>').join('');
       return '<details id="coverage-finding-'+h(item.id)+'"><summary>'+h([item.study,item.title,labels[item.provenance]].filter(Boolean).join(' · '))+'</summary>'+
        (item.cohort?'<p class="coverage-note">'+h([item.cohort,item.cutoff].filter(Boolean).join(' · '))+'</p>':'')+
        '<p>'+h(item.interpretation)+'</p>'+compare(item,'study detail comparison')+(minima?'<ul>'+minima+'</ul>':'')+
        '<p>'+h(item.limitations)+'</p><p class="coverage-note">'+cite(item.refs)+'</p></details>';
     }).join(''):'';
  }
  function selectVariation(id,preferredFamily) {
    if (id!==active.variation) {
      active.variation=id;
      if (!preferredFamily) active.family=current().observations[0]?.family || active.family;
      const selected=current().graph;
      if (selected && hasGraph) {
        active.objective=selected.objective;
        active.route=selected.route;
        active.reveal=1;
      }
      routeView();
    }
    if (preferredFamily) active.family=preferredFamily;
    selectState(); detail(); guidance();
  }
  root.addEventListener('click',(event)=>{
    const link=event.target.closest('a[href^="#coverage-finding-"]');
    if (link) {
      const details=at('coverage-evidence').closest('details');
      if (details) details.open=true;
      const finding=at(link.hash.slice(1));
      if (finding) {
        finding.open=true;
        requestAnimationFrame(()=>{
          const summary=finding.querySelector('summary');
          summary.focus({preventScroll:true});
          summary.scrollIntoView({behavior:'instant',block:'center'});
        });
      }
    }
    const button=event.target.closest('button');
    if (!button) return;
    if (button.dataset.variation || button.dataset.family) {
      selectVariation(button.dataset.variation || active.variation,button.dataset.family);
    }
    if (button.id==='coverage-reveal') { active.reveal++; routeView(); }
    if (button.id==='coverage-reset-path') { active.reveal=1; routeView(); }
  });
  root.addEventListener('change',(event)=>{
    const target=event.target;
    if (target.matches('.coverage-variation')) selectVariation(target.value);
    if (target.id==='coverage-family') selectVariation(active.variation,target.value);
    if (target.id==='coverage-preset' && target.value!=='custom') {
      active.preset=target.value;
      active.collection=new Set(data.presets.find((preset)=>preset.id===target.value).sources);
      guidance();
    }
    if (target.dataset.collection) {
      const id=target.dataset.collection;
      if (target.checked) active.collection.add(id); else active.collection.delete(id);
      active.preset='custom'; guidance();
    }
    if (target.id==='coverage-objective') {
      active.objective=target.value;
      active.route=graph.objectives.find((objective)=>objective.id===active.objective).routes[0].id;
      active.reveal=1; routeView();
    }
    if (target.id==='coverage-route') {
      active.route=target.value; active.reveal=1; routeView();
    }
    if (target.id==='coverage-placement-select') { active.placement=target.value; placement(); }
  });
  at('coverage-deck').textContent=data.deck;
  at('coverage-scope').textContent=data.scope;
  displayMatrix(); guidanceControls(); graphControls(); renderExamples(); renderStudies();
  if (defaultVariation.graph && hasGraph) {
    active.objective=defaultVariation.graph.objective; active.route=defaultVariation.graph.route;
  }
  selectState(); detail(); guidance(); routeView(); placement();

}

async function readCoverage(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error('Coverage content unavailable');
  return response.json();
}

async function initializeCoverage(root) {
  const status = root.querySelector('#coverage-loading');
  status.hidden = false;
  try {
    const data = await readCoverage(root.dataset.profile);
    if (!validProfile(data)) throw new Error('Unsupported coverage profile');
    const graph = data.behavioralGraph
      ? await readCoverage(sitePath(data.behavioralGraph.path, root.dataset.baseurl))
      : {objectives:[]};
    if (data.behavioralGraph &&
        (!graph.objectives?.length || graph.baseline?.siteCommit !== data.behavioralGraph.baseline)) {
      throw new Error('Unsupported graph');
    }
    for (const {graph: relation} of data.variations) {
      if (relation && !approvedRoute(graph, relation.objective, relation.route)) {
        throw new Error('Coverage route unavailable');
      }
    }
    mountCoverage(root, data, graph);
    root.querySelector('#coverage-interface').hidden = false;
    status.hidden = true;
  } catch {
    status.textContent = 'Defensive coverage is unavailable. Read the detection notes or rules below.';
  }
}

if (typeof document !== 'undefined') {
  const root = document.querySelector('#defensive-coverage[data-profile]');
  if (root) initializeCoverage(root);
}
