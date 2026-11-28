import {
  goals, subsets, mask, minima, finalPoint, observed, difference, earliest, withAdd,
  measuredAdvice, qualitativeAdvice, shapley, frontier, priorityAdvice
} from "./telemetry-value-model.mjs";
import {projectStudy} from "./telemetry-value-study.mjs";

export function mountValue(root, {profile, study, appendix}) {
  const field = id => root.querySelector("#tv-"+id);
  const h = value => String(value ?? "").replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[char]);
  const labels = Object.fromEntries(profile.capabilities.map(item=>[item.id,item.label]));
  const origins = Object.fromEntries(profile.capabilities.map(item=>[item.id,item.origin]));
  const refs = Object.fromEntries(profile.references.map(item=>[item.id,item]));
  const cutoffName = ms => ms === null ? "Final replay" : ms === 1000 ? "1 s" : ms === 5000 ? "5 s" : ms+" ms";
  const tag = (text, state="context") => '<span class="coverage-tag state-'+state+'">'+h(text)+'</span>';
  const bundle = ids => ids.length ? ids.map(id=>h(labels[id])).join(" + ") : "Current collection";
  const bundles = sets => sets.map(bundle).join(" or ");
  const names = {source:"Source-supported", measured:"Measured", synthetic:"Synthetic", hypothesis:"Hypothesis"};
  const ratio = row => row ? row[0]+"/"+row[1] : "Unmeasured";
  const metricNames = study?.metrics || {};
  const link = ref => '<a href="'+h(ref.url)+'">'+h(ref.title)+'</a>'+(ref.locator ? ' <small>'+h(ref.locator)+'</small>' : '');
  const state = {variant:null, baseline:new Set(), goal:"hunt", timing:"causal", disputed:false,
                 weights:{effect:0,causal:0,authorization:0}, costs:{}, additive:false};
  const option = (id,name) => '<option value="'+h(id)+'">'+h(name)+'</option>';
  const block = (title, body) => '<div class="tv-answer"><h4>'+title+'</h4>'+body+'</div>';
  const p = content => '<p>'+content+'</p>';
  const list = entries => '<ul>'+entries.map(entry=>'<li>'+entry+'</li>').join("")+'</ul>';
  const table = (title, cols, rows) => '<div class="coverage-scroll" tabindex="0" role="region" aria-label="'+h(title)+'"><table><thead><tr>'+cols.map(x=>'<th scope="col">'+h(x)+'</th>').join("")+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map((cell,i)=>i===0?'<th scope="row">'+cell+'</th>':'<td>'+cell+'</td>').join("")+'</tr>').join("")+'</tbody></table></div>';
  const current = () => profile.variations.find(item=>item.id===state.variant);

  function setup(id, direct=true) {
    state.variant=id;
    const item=current();
    state.baseline=new Set(item.baseline);
    state.goal=direct ? item.defaultGoal || "causal" : state.goal;
    state.costs={};
    state.additive=false;
    delete field("cost-inputs").dataset.for;
    state.disputed=false;
    field("variation").value=id;
    field("goal").value=state.goal;
    field("conflict").checked=false;
    field("capabilities").innerHTML=item.capabilities.map(id=>{
      const cap=profile.capabilities.find(x=>x.id===id);
      return '<label class="coverage-check"><input type="checkbox" data-cap="'+h(id)+'"><span>'+h(cap.label)+'<small>'+h(cap.description)+'</small></span></label>';
    }).join("");
    field("lab-details").hidden=!(item.study && study);
    field("advanced").hidden=!(item.study && study);
    field("appendix").hidden=!appendix;
    const exercise = item.explorer && root.dataset.explorer
      ? root.dataset.explorer+"?"+new URLSearchParams(item.explorer) : "";
    field("link").innerHTML=exercise ? '<a href="'+h(exercise)+'">Open this Lens Explorer exercise</a>' : '';
    render();
  }

  function claimAdvice(qual, goal, blocked) {
    if (blocked) return p("Resolve the source or join conflict before relying on a combined finding.");
    const matching=qual.target;
    if (goal==="earlier") return p("Timing is unmeasured for this variation. Compare event occurrence, arrival and when the last required record arrives.");
    if (!matching.length) return p("The documented evidence cannot rank collection for this outcome. Try another objective or inspect the scope below.");
    if (!qual.next.length) return p("The selected evidence covers the documented dependencies. Verify the joins before adding collection.");
    return qual.next.map(item=>p('<strong>'+bundles(item.sets)+'</strong>. '+h(item.limit))).join("");
  }
  function conditionalClaims(qual) {
    const available=qual.evaluated.filter(c=>c.satisfied);
    const blocked=qual.evaluated.filter(c=>!c.satisfied&&c.known);
    const unavailable=qual.evaluated.filter(c=>!c.known&&!c.blockedByOrigin);
    const origin=qual.evaluated.filter(c=>c.blockedByOrigin);
    return (available.length ? list(available.map(c=>'<strong>'+h(c.label)+'</strong>. '+h(c.qualification)))
      : p("The selected evidence supplies context. The scoped claims still need corroboration."))+
      (blocked.length ? p('<small>Still open · '+blocked.map(c=>h(c.label)).join(" · ")+'</small>') : "")+
      (unavailable.length ? p('<small>Unavailable in the named capture · '+unavailable.map(c=>h(c.label)).join(" · ")+'</small>') : "")+
      (origin.length ? p('<small>Independent origin required · '+origin.map(c=>h(c.label)).join(" · ")+'</small>') : "");
  }
  function timingReadout(study, metric, before, after) {
    if (!metric) return "Unmeasured for this objective.";
    const indexA=earliest(study,before,metric),indexB=earliest(study,after,metric);
    const time = index => index < 0 ? "No full qualification at a recorded cutoff" : cutoffName(study.points[index].cutoffMs);
    return h(time(indexA))+" → "+h(time(indexB))+". Study evidence availability.";
  }
  function scopeTable(item, before, after, activeMetric) {
    const point=study ? finalPoint(study) : null;
    function gains(metric) {
      if (!point||!(item.study && study)) return "Unmeasured.";
      const d=difference(study,point,metric,before,after);
      return d ? ratio(d.before)+" → "+ratio(d.after)+" ("+ (d.gain>=0?"+":"")+d.gain+")" : "Unknown or incomparable.";
    }
    const route=item.explorer && appendix?.objectives.find(x=>x.id===item.explorer.objective)?.routes.find(x=>x.id===item.explorer.route);
    const active=item.capabilities.filter(id=>state.baseline.has(id)&&item.hunt[id]);
    const places = (route ? "Modeled route · "+h(route.name)+". " : "Variation · "+h(item.title)+". ") +
      (active.length?"Applicable baseline opportunities · "+bundle(active)+". ":"No mapped opportunities in the current selection. ")+
      "Empirical coverage is unmeasured.";
    return '<dl class="tv-dimensions"><dt>Behavioral coverage</dt><dd>'+places+'</dd><dt>Effect confirmation</dt><dd>'+gains("effect")+
      '</dd><dt>Detection fidelity</dt><dd>Production fidelity unmeasured.'+((item.study && study)?" Downstream authorization qualification "+gains("authorization"):"")+
      '</dd><dt>Attribution</dt><dd>No standalone measured attribution result.</dd><dt>Causal reconstruction</dt><dd>'+gains("causal")+
      '</dd><dt>Timeliness</dt><dd>'+((item.study && study)?timingReadout(study,activeMetric,before,after):"Unmeasured for this variation.")+
      '</dd><dt>Operational cost</dt><dd>'+costText(item)+'</dd></dl>';
  }
  function costText(item) {
    if (!(item.study && study) || !state.additive) return "Unmeasured. Add scoped effort estimates only when useful.";
    const missing=study.lenses.filter(id=>!state.baseline.has(id));
    return missing.every(id=>Object.hasOwn(state.costs,id))
      ? "Your incremental staff-hour estimates per month. See cost tradeoffs below."
      : "Estimates are incomplete. Cost comparison is unavailable.";
  }
  function studyControls(metric) {
    const point=finalPoint(study), before=mask(study,state.baseline);
    const measuredRows=study.points.map(p=>[h(cutoffName(p.cutoffMs)),
      ...["effect","causal","authorization"].map(id=>h(ratio(observed(p,before,id))))]);
    field("minimum").innerHTML=list(["effect","causal","authorization","boundary"].map(claim=>
      '<strong>'+h(metricNames[claim])+'</strong> · '+bundles(minima(study,point,claim))))+
      p('<small>Final replay. Qualifies when all eligible positive cases are confirmed and the explicit false-confirmation count is zero.</small>');
    field("matrix").innerHTML=table("Recorded cutoff results",["Cutoff","Effect","Causal","Authorization"],measuredRows)+
      (metric ? table("Final replay consideration of all additions",["Add to baseline","Confirmed / eligible","Change","False confirmations"],
        subsets(study.lenses.filter(id=>!state.baseline.has(id))).map(ids=>{
          const after=withAdd(study,state.baseline,ids), d=difference(study,point,metric,before,after);
          return [bundle(ids),h(d ? ratio(d.after) : "Unknown"),h(d ? (d.gain>=0?"+":"")+d.gain : "Unknown"),h(d?.after[3] ?? "Unknown")];
        })) : p("Choose a measured objective to compare all additions."))+
      p('<small>The reproduced final-replay tables retain the eligible denominator for each claim.</small>');
    const phi=metric ? shapley(study,point,metric) : null;
    field("shapley").innerHTML=phi ? p('Mean marginal confirmed '+h(metricNames[metric].toLowerCase())+' across all recorded final-replay subsets.')+
      table("Shapley contribution",["Capability","Mean contribution"],Object.entries(phi).map(([id,v])=>[h(labels[id]),h(Number(v.toFixed(3)))]))
      : p("This target lacks a complete comparable subset result.");
    const qualified=priorityAdvice(study,state.baseline,state.weights);
    field("weight-result").innerHTML=!qualified ? p("Set a priority to compare another recommendation. Larger weights set first priority. Equal leading weights preserve tradeoffs.")
        : qualified.unknown ? p("Incomplete results for these leading priorities. No composite score.")
        : p("Leading priority · "+qualified.metrics.map(x=>h(metricNames[x])).join(" and ")) +
          list(qualified.choices.map(x=>bundle(x.add)+" · "+x.gains.map((g,i)=>h(metricNames[qualified.metrics[i]])+" "+(g.gain>=0?"+":"")+g.gain).join(" · ")))+
          p("<small>Each count keeps its own eligible denominator. Priorities are your preferences; the counts come from final replay.</small>");
    const missing=study.lenses.filter(id=>!state.baseline.has(id));
    const signature=missing.join("");
    if (field("cost-inputs").dataset.for!==signature) {
      field("cost-inputs").dataset.for=signature;
      field("cost-inputs").innerHTML=missing.map(id=>'<label>'+h(labels[id])+'<input type="number" min="0" step="any" inputmode="decimal" data-cost="'+id+'" value="'+(state.costs[id]??'')+'"></label>').join("");
    }
    field("additive").checked=state.additive;
    const pareto=metric&&state.additive ? frontier(study,state.baseline,metric,state.costs) : null;
    field("pareto").innerHTML=pareto ? table("Nondominated cost and gain options",["Add to baseline","Effort (hours/month)","Confirmed change"],
      pareto.map(x=>[bundle(x.add),h(x.cost),h((x.delta.gain>=0?"+":"")+x.delta.gain)])) :
      p("Comparable estimates are needed for every candidate capability. Blank means unknown.");
  }
  function appendixView(item) {
    if (!appendix) return;
    const src=appendix.variations.find(v=>v.id===item.id);
    const compatible=item.explorer && appendix.objectives.find(x=>x.id===item.explorer.objective);
    const route=compatible?.routes.find(r=>r.id===item.explorer.route);
    field("graph").innerHTML=route ? p(h(route.name)+" · "+h(route.provenance))+
      '<ol class="coverage-graph">'+route.requiredBehavioralStages.map(node=>'<li><span class="coverage-node">'+h(node)+'</span></li>').join("")+'</ol>'+
      p(h(route.exactBindingRequirement)) : p("There is no modeled route excerpt for this variation.");
    field("observations").innerHTML=src ? table("Approved observation matrix slice",["Family","Evidence status","Opportunity and limit"],
      src.observations.map(x=>[h(appendix.observationFamilies.find(r=>r.id===x.family).label),h(({source:"Source-supported",measured:"Measured",synthetic:"Synthetic",context:"Supporting context",unavailable:"Unavailable",hypothesis:"Hypothesis"})[x.state]),h(x.relevance)+" "+h(x.limit)])) : "";
    if (!field("samples").childElementCount) {
      const examples=appendix.evidenceExamples.map(x=>'<details><summary>'+h(x.title+' · '+({"native-projection":"Native, sanitized", supplemental:"Supplemental instrumentation", synthetic:"Synthetic"})[x.provenance])+
        '</summary>'+table(x.title,["Field","Value"],x.fields.map(f=>[h(f.field),h(f.value)]))+
        p(h(x.establishes)) + p(h(x.limits)) + p(h(x.strengthen)) + p(h(x.administrative)) + '</details>');
      const findings=appendix.findings.filter(f=>f.id!=="delegated-effect-v-cause").map(f=>'<details><summary>'+h(f.study+" · "+f.title)+'</summary>'+
        p(h(f.interpretation)) + list(f.comparisons.map(row=>h(row.label)+" · "+row.metrics.map(metric=>metric.confirmed+"/"+metric.denominator+" "+h(metric.label)).join(" · ")))+
        p(h(f.limitations))+'</details>');
      field("samples").innerHTML=examples.join("")+findings.join("");
    }
  }

  function render() {
    const item=current();
    field("capabilities").querySelectorAll("[data-cap]").forEach(el=>el.checked=state.baseline.has(el.dataset.cap));
    field("baseline").textContent=state.baseline.size ? item.capabilities.filter(id=>state.baseline.has(id)).map(id=>labels[id]).join(" · ") : "No capabilities selected";
    field("earlier").hidden=state.goal!=="earlier"||!(item.study && study);
    field("presets").hidden=!(item.study && study);
    field("evidence-label").innerHTML=tag(names[item.maturity],item.maturity)+((item.study && study)?' <small>Gate C.2 · Delegated workload · Augmented replay</small>':'');
    const qual=qualitativeAdvice(item,state.baseline,state.goal,state.disputed,origins);
    const advice=(item.study && study) ? measuredAdvice(study,state.baseline,state.goal,state.timing) : null;
    const currentMask=(item.study && study) ? mask(study,state.baseline) : "";
    const metric=advice?.metric;
    const valid=advice && !advice.unknown;
    const start = valid ? (advice.qualifying.length ? p('<strong>'+bundles(advice.qualifying)+'</strong> qualifies for '+h(metricNames[metric].toLowerCase())+'.') : p("No smallest qualifying set was established.")) :
      (qual.start.length ? qual.start.map(s=>p('<strong>'+bundles(s.sets)+'</strong> · '+h(s.label))).join("") : p("No qualifying collection set has been established for this objective."));
    const hunts=item.capabilities.filter(id=>state.baseline.has(id)&&item.hunt[id]).map(id=>h(item.hunt[id]));
    let claims=conditionalClaims(qual), add=claimAdvice(qual,state.goal,state.disputed), gain= "";
    const chosen=valid && advice.best.length && !state.disputed ? advice.best[0] : [];
    let after=(item.study && study) ? withAdd(study,state.baseline,chosen) : "";
    if (valid && !state.disputed) {
      const point=finalPoint(study);
      claims=p('<strong>'+h(ratio(observed(point,currentMask,"effect")))+'</strong> downstream effects · <strong>'+
        h(ratio(observed(point,currentMask,"causal")))+'</strong> causal relationships in final replay.')+
        (metric==="authorization" ? p(h(ratio(observed(point,currentMask,"authorization")))+" downstream authorization qualifications. Production detection fidelity is unmeasured.") : "")+
        p('<small>'+h((qual.target[0]||qual.evaluated.find(c=>c.id===metric))?.qualification || item.limitation)+'</small>');
      if (advice.best.length) {
        add=p('<strong>'+bundles(advice.best)+'</strong>. '+(advice.best.length>1?'These additions tie for this study objective.':'Start with this addition given the selected baseline.'));
        gain=advice.best.map(extra=>{
          const candidate=withAdd(study,state.baseline,extra);
          const effects=difference(study,point,"effect",currentMask,candidate);
          const causal=difference(study,point,"causal",currentMask,candidate);
          const auth=difference(study,point,"authorization",currentMask,candidate);
          const prefix=advice.best.length>1 ? bundle(extra)+" · " : "";
          return p(prefix+'<strong>'+ (effects.gain>=0?"+":"")+effects.gain+'</strong> downstream effects ('+ratio(effects.before)+' → '+ratio(effects.after)+
            ') · <strong>'+(causal.gain>=0?"+":"")+causal.gain+'</strong> causal relationships ('+ratio(causal.before)+' → '+ratio(causal.after)+').')+
            (metric==="authorization"?p('<strong>+'+auth.gain+'</strong> downstream authorization qualifications. Production detection fidelity remains unmeasured.'): '')+
            (state.goal==="earlier" ? p(timingReadout(study,metric,currentMask,candidate)) : '');
        }).join("");
      } else {
        add=p("Keep the current set for this objective. The replay shows no supported improvement from adding a capability.");
        gain=p("No additional measured gain for the selected claim. A different objective can change the recommendation.");
      }
    }
    if ((item.study && study) && !valid) {
      gain=p("The selected study has no numerical result for this outcome. Use the documented evidence requirements.");
    }
    if (!gain) gain=qual.next.length ? p(qual.next.map(c=>h(c.label)).join(" · ")+". Claim support depends on traceable fields and qualified joins.") :
      qual.target.length ? p("The current selection covers the documented dependencies. Additional benefit is unmeasured.") :
      p("The available evidence does not establish a collection gain for this outcome.");
    if (state.disputed) {
      claims=p("The selected records or their binding are disputed. Keep the affected claims open. The study tables still describe the frozen replay.");
      add=p("Resolve the actor, object, timing or shared-origin conflict before adding collection to support the disputed claim.");
      gain=p("Investigation value may come from correcting the join. The prototype does not rank the impact of conflicts.");
    }
    field("results").innerHTML=block("Start here",start)+block("What to look for",hunts.length?p(hunts.join(" ")):p("Select the records you can scope to this variation."))+
      block("What you can establish",claims)+block("What to add next",add)+block("What you gain",gain)+block("Collection cost",p(h(costText(item))));
    field("dimensions").innerHTML=state.disputed ? p("Live evidence remains disputed. Resolve the joins before assessing value by dimension.") : (advice?.best?.length>1?p("Comparison below uses "+bundle(chosen)+". See What you gain for each alternative."):"")+scopeTable(item,currentMask,after,metric);
    field("scope").innerHTML=p(h(item.limitation))+
      p('<strong>Administrative equivalent</strong> '+h(item.legitimate))+
      list(item.refs.map(id=>link(refs[id])));
    if ((item.study && study)) studyControls(metric);
    appendixView(item);
    state.onRelevanceChange?.();
    updateRuleAvailability();
  }
  function updateRuleAvailability() {
    for (const rule of root.querySelectorAll("[data-ce-sigma]")) {
      const status=rule.querySelector("[data-ce-sigma-status]");
      const needed=JSON.parse(rule.dataset.requires);
      if (rule.dataset.variation!==state.variant) {
        status.textContent="Mapped to "+profile.variations.find(item=>item.id===rule.dataset.variation).title+
          ". Select that variation to check its collection.";
      } else if (state.disputed) {
        status.textContent="Source or join unresolved. Verify the field mapping before applying this candidate.";
      } else if (needed.every(id=>state.baseline.has(id))) {
        status.textContent="Applicable capability selected. Verify the exact stream and fields below.";
      } else {
        status.textContent="Collection gap · "+needed.filter(id=>!state.baseline.has(id)).map(id=>labels[id]).join(" + ")+".";
      }
    }
  }

  field("variation").innerHTML=profile.variations.map(v=>option(v.id,v.title)).join("");
  field("goal").innerHTML=Object.entries(goals).map(([id,label])=>option(id,label)).join("");
  field("variation").addEventListener("change",e=>setup(e.target.value,false));
  field("goal").addEventListener("change",e=>{state.goal=e.target.value;render();});
  field("timing").addEventListener("change",e=>{state.timing=e.target.value;render();});
  field("panel").addEventListener("change",e=>{
    const el=e.target;
    const {cap,weight,cost}=el.dataset;
    if (cap) {if(el.checked) state.baseline.add(cap); else state.baseline.delete(cap);render();}
    if (weight) {state.weights[weight]=Number(el.value)||0;render();}
    if (cost) {
      if(el.value===""||!el.validity.valid) delete state.costs[cost];
      else state.costs[cost]=Number(el.value);
      render();
    }
    if(el===field("additive")){state.additive=el.checked;render();}
    if(el===field("conflict")){state.disputed=el.checked;render();}
  });
  field("presets").addEventListener("click",e=>{
    const preset=e.target.dataset.preset;
    if(preset===undefined)return;
    state.baseline=new Set(preset);
    render();
  });
  setup(profile.defaultVariation || profile.variations[0].id);

  function mountRelevance(matrix) {
    if (!matrix || matrix.format!=="telemetry-relevance/v1") return;

    const roles = {
      primary:["P","Primary"], complementary:["C","Complementary"],
      context:["S","Supporting context"], limited:["L","Limited"], unknown:["?","Unknown"]
    };
    const basis = {
      source:["SRC","Source-supported"], measured:["LAB","Measured fixture"],
      synthetic:["SYN","Synthetic"], hypothesis:["HYP","Hypothesis"]
    };
    const rowLabels = new Map(matrix.rows.map(row=>[row.id,row]));
    const variants = new Map(profile.variations.map(variation=>[variation.id,variation]));
    const key = (row,variation) => row+"|"+variation;
    const index = new Map(matrix.cells.map(cell=>[key(cell.row,cell.variation),cell]));
    const unknown = {role:"unknown",basis:null};
    const locate = (row,variation) => index.get(key(row,variation)) || unknown;
    let selected = null;
    const section = field("relevance");
    const inspector = field("relevance-inspector");
    const summary = inspector.querySelector("summary");
    const picker = field("relevance-row");
    const desktop = field("relevance-grid");
    const mobile = field("relevance-mobile-rows");
    const inspectorBody = field("relevance-info");
    const columns = matrix.columns;
    const tradecraftCount = columns.filter(col=>!col.kind || col.kind==="tradecraft").length;
    const comparisonCount = columns.length-tradecraftCount;
    const firstComparison = comparisonCount ? columns[tradecraftCount].variation : null;
    const comparisonClass = col => col.variation===firstComparison ? ' class="tvr-comparison-start"' : '';
    const kindName = col => col.kind==="diagnostic"?"Diagnostic":col.kind==="synthetic"?"Synthetic":"";
    const columnLabel = col => h(col.label)+(kindName(col)?'<span class="tvr-kind">'+kindName(col)+'</span>':'');

    function button(row, col) {
      const cell = locate(row.id,col.variation);
      const role = roles[cell.role];
      const evidence = basis[cell.basis];
      const code = role[0]+(evidence?" "+evidence[0]:"");
      const name = code+" · "+row.label+" · "+variants.get(col.variation).title+
        (kindName(col)?" · "+kindName(col):"")+" · "+role[1]+
        (evidence?" · "+evidence[1]:"");
      const pressed = selected?.row===row.id && selected?.variation===col.variation;
      return '<button type="button" class="tvr-cell tvr-'+h(cell.role)+'" data-tvr-row="'+h(row.id)+
        '" data-tvr-variation="'+h(col.variation)+'" aria-controls="tv-relevance-inspector"'+
        ' aria-pressed="'+Boolean(pressed)+'" title="'+h(name)+'" aria-label="'+h(name)+'">'+
        '<span aria-hidden="true" class="tvr-symbol">'+h(role[0])+'</span>'+
        (evidence?' <span aria-hidden="true" class="tvr-basis">'+h(evidence[0])+'</span>':'')+'</button>';
    }

    function mobileRows() {
      const row = rowLabels.get(picker.value);
      mobile.innerHTML = columns.map(col=>'<tr'+comparisonClass(col)+'><th scope="row">'+columnLabel(col)+'</th><td>'+
        button(row,col)+'</td></tr>').join("");
    }

    const head = comparisonCount
      ? '<tr class="tvr-column-groups"><th scope="col" rowspan="2">Telemetry</th><th scope="colgroup" colspan="'+tradecraftCount+
        '">Tradecraft variations</th><th scope="colgroup" class="tvr-comparison-start tvr-comparison-group" colspan="'+comparisonCount+
        '">Comparison cases</th></tr><tr>'
      : '<tr><th scope="col">Telemetry</th>';
    const columnGroups = comparisonCount
      ? '<colgroup><col span="'+tradecraftCount+'"></colgroup><colgroup><col span="'+comparisonCount+'"></colgroup>'
      : '<colgroup><col span="'+columns.length+'"></colgroup>';
    desktop.innerHTML = '<colgroup><col class="tvr-telemetry"></colgroup>'+columnGroups+'<thead>'+head+
      columns.map(col=>'<th scope="col"'+comparisonClass(col)+' title="'+h(variants.get(col.variation).title)+'">'+columnLabel(col)+'</th>').join("")+
      '</tr></thead><tbody>'+matrix.rows.map(row=>'<tr><th scope="row">'+h(row.label)+'</th>'+
        columns.map(col=>'<td'+comparisonClass(col)+'>'+button(row,col)+'</td>').join("")+'</tr>').join("")+'</tbody>';
    picker.innerHTML = matrix.rows.map(row=>option(row.id,row.label)).join("");
    picker.value = matrix.defaultRow;
    mobileRows();

    function inspect() {
      if (!selected) return;
      const {row,variation} = selected;
      const cell = locate(row,variation);
      const variant = variants.get(variation);
      const heading = rowLabels.get(row).label+" · "+variant.title;
      const evidence = basis[cell.basis];
      field("relevance-title").textContent = heading;
      const relation = (cell.claims || []).map(id=>variant.claims.find(claim=>claim.id===id));
      const requires = relation.length ? list(relation.map(claim=>
        '<strong>'+h(claim.label)+'</strong> · '+(claim.requiresAny.length ? bundles(claim.requiresAny):
          'Unavailable in the named capture.'))):p("No recommendation claim is linked to this cell.");
      const mapped = (cell.capabilities || []).map(id=>profile.capabilities.find(cap=>cap.id===id));
      const fieldList = (cell.requiredFields || []).map(h);
      const listOfRefs = (cell.refs || []).map(id=>link(refs[id]));
      const rules=[...root.querySelectorAll("[data-ce-sigma]")].filter(rule=>
        rule.dataset.variation===variation && rule.dataset.row===row);
      const loaded = state.variant===variation;
      const held = loaded ? mapped.filter(cap=>state.baseline.has(cap.id)).map(cap=>h(cap.label)) : [];
      const column=columns.find(col=>col.variation===variation);
      const tags = tag(roles[cell.role][1]) + (evidence ? ' '+tag(evidence[1],cell.basis) : '')+
        (kindName(column) ? ' '+tag(kindName(column)+" comparison") : '');
      const scopeText = evidence && cell.basis==="measured" ?
        '<small>Measured evidence is limited to the cited fixture and claim.</small>' : '';
      const available = loaded && mapped.length ? p('<small>Selected here · '+(held.length?held.join(" · "):"None of the mapped capabilities")+'</small>') : '';
      const unknownText = "No scoped assessment is recorded for this capability and variation. Its value remains unknown.";
      inspectorBody.innerHTML = '<div class="coverage-tags">'+tags+scopeText+'</div>'+
        p(h(cell.rationale || unknownText)) +
        (fieldList.length ? '<h5>Required fields</h5>'+list(fieldList) : '')+
        (mapped.length ? '<h5>Profile capabilities</h5>'+p(mapped.map(x=>h(x.label)).join(" · "))+available : '')+
        '<h5>Evidence dependencies</h5>'+requires+
        '<h5>Limits</h5>'+p(h(cell.limitation || "The comparison gives no collection recommendation for this pairing."))+
        (listOfRefs.length ? '<h5>Supporting sources</h5>'+list(listOfRefs) : '')+
        (rules.length ? '<h5>Sigma candidates</h5>'+list(rules.map(rule=>'<a data-ce-rule-link href="#'+h(rule.id)+
          '">'+h(rule.querySelector(".det-rule-title").textContent)+'</a>')) : '')+
        '<button class="tvr-return" type="button" id="tv-relevance-back">Back to selected cell</button> ' +
        (loaded ? '' : '<button id="tv-relevance-load" type="button">Use this variation in recommendations</button>'+
          '<small class="tvr-load-note">Loads that variation’s illustrative baseline.</small>');
    }

    function activate(row,variation,keyboard) {
      selected = {row,variation};
      section.querySelectorAll("[data-tvr-row]").forEach(button=>{
        button.setAttribute("aria-pressed",String(button.dataset.tvrRow===row&&button.dataset.tvrVariation===variation));
      });
      if (picker.value!==row) {
        picker.value=row;
        mobileRows();
      }
      inspect();
      inspector.open=true;
      if (keyboard) summary.focus({preventScroll:true});
      const rect = summary.getBoundingClientRect();
      if (rect.top<72 || rect.bottom>innerHeight-72 || keyboard) {
        summary.scrollIntoView({block:"center",behavior:"instant"});
      }
    }

    section.addEventListener("click",event=>{
      const ruleLink=event.target.closest("[data-ce-rule-link]");
      if (ruleLink) {
        const rule=document.getElementById(ruleLink.hash.slice(1));
        if (rule) {
          event.preventDefault();
          history.replaceState(null,"",ruleLink.hash);
          rule.open=true;
          const target=rule.querySelector("summary");
          target.focus({preventScroll:true});
          target.scrollIntoView({block:"center",behavior:"instant"});
        }
      }
      const cell=event.target.closest("[data-tvr-row]");
      if (cell) activate(cell.dataset.tvrRow,cell.dataset.tvrVariation,event.detail===0);
      if (event.target.closest("#tv-relevance-back") && selected) {
        if (picker.value!==selected.row) {
          picker.value=selected.row;
          mobileRows();
        }
        const origin=Array.from(section.querySelectorAll('[data-tvr-row][aria-pressed="true"]'))
          .find(button=>button.getClientRects().length);
        origin?.focus();
      }
      if (event.target.closest("#tv-relevance-load") && selected) {
        const goal=field("goal");
        setup(selected.variation,false);
        goal.focus();
      }
    });
    picker.addEventListener("change",mobileRows);
    state.onRelevanceChange=inspect;
    section.hidden=false;
  }
  mountRelevance(profile.relevanceMatrix);
}

async function readJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error("Coverage data is unavailable.");
  return response.json();
}

async function initializeValue(root) {
  const loading=root.querySelector("#coverage-loading");
  loading.hidden=false;
  try {
    const [profile, coverage]=await Promise.all([
      readJson(root.dataset.value), readJson(root.dataset.profile)
    ]);
    if (profile.format!=="telemetry-value/v1" || !profile.variations?.length ||
        (profile.variations.some(variation=>variation.study) && !profile.studySelection)) {
      throw new Error("Unrecognized coverage profile.");
    }
    const [dataset,graph]=await Promise.all([
      profile.studySelection && readJson(root.dataset.baseurl+"/assets/data/detection-lens-explorer.v1.json"),
      coverage.behavioralGraph && readJson(root.dataset.baseurl+coverage.behavioralGraph.path)
    ]);
    const study=dataset ? projectStudy(dataset,profile.studySelection) : null;
    const appendix=(coverage.variations || coverage.evidenceExamples || graph) ? {
      observationFamilies:coverage.observationFamilies || [],
      variations:coverage.variations || [],
      evidenceExamples:coverage.evidenceExamples || [],
      findings:coverage.findings || [],
      objectives:graph?.objectives || []
    } : null;
    mountValue(root,{profile,study,appendix});
    root.querySelector("#tv-panel").hidden=false;
    loading.hidden=true;
  } catch {
    loading.textContent="Defensive coverage is unavailable. Read the detection notes or rules below.";
  }
}

if (typeof document!=="undefined") {
  const root=document.querySelector("#defensive-coverage[data-value]");
  if (root) initializeValue(root);
}

