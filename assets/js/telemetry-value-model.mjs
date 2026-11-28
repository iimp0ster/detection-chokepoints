const goals = {
  hunt: "Start hunting", effect: "Confirm an effect", fidelity: "Improve detection fidelity",
  attribution: "Attribute activity", causal: "Reconstruct the attack chain", earlier: "Detect earlier"
};
const goalMetric = {effect:"effect", causal:"causal", fidelity:"authorization", earlier:"causal"};

function subsets(items) {
  return items.reduce((list, item) => [...list, ...list.map(set => [...set, item])], [[]]);
}
function mask(study, selected) {
  return study.lenses.filter(id => selected.has(id)).join("");
}
function includesAll(have, requested) {
  return requested.every(id => have.has(id));
}
function uniqueSets(groups) {
  return [...new Map(groups.map(group => [[...group].sort().join("/"), group])).values()];
}
function smallest(groups) {
  const size = Math.min(...groups.map(group => group.length));
  return uniqueSets(groups.filter(group => group.length === size));
}
function minimal(groups) {
  return uniqueSets(groups).filter(group => !groups.some(other =>
    other.length < group.length && includesAll(new Set(group), other)));
}
function finalPoint(study) { return study.points.find(point => point.cutoffMs === null); }
function observed(point, key, metric) {
  const row = point?.rows[key]?.[metric];
  return row && row[1] > 0 ? row : null;
}
function qualifying(row) {
  return row !== null && row[0] === row[1] && row[3] === 0;
}
function minima(study, point, metric) {
  return smallest(Object.keys(point.rows).filter(key => qualifying(observed(point, key, metric))).map(key => [...key]));
}
function difference(study, point, metric, before, after) {
  const a = observed(point, before, metric);
  const b = observed(point, after, metric);
  if (!a || !b || a[1] !== b[1] || a[3] === null || b[3] === null) return null;
  return {gain:b[0]-a[0], falseChange:b[3]-a[3], before:a, after:b};
}
function earliest(study, key, metric) {
  return study.points.findIndex(point => qualifying(observed(point, key, metric)));
}
function withAdd(study, baseline, extra) {
  return mask(study, new Set([...baseline, ...extra]));
}
function candidates(study, baseline, metric) {
  const before = mask(study, baseline);
  const point = finalPoint(study);
  return subsets(study.lenses.filter(id => !baseline.has(id))).map(add => {
    const after = withAdd(study, baseline, add);
    return {
      add, after, delta:difference(study,point,metric,before,after),
      earliest:earliest(study,after,metric)
    };
  }).filter(row => row.delta !== null && row.delta.after[3] === 0 && row.delta.falseChange <= 0);
}
function measuredAdvice(study, baseline, goal, timingMetric="causal") {
  const metric = goal === "earlier" ? timingMetric : goalMetric[goal];
  if (!metric) return null;
  const before = mask(study, baseline);
  const point = finalPoint(study);
  const row = observed(point,before,metric);
  if (!row) return {metric, unknown:true};
  const currentTime = earliest(study,before,metric);
  const options = candidates(study,baseline,metric);
  const current = options.find(candidate => candidate.add.length===0);
  if (!current || !options.length) return {metric,unknown:true};
  const earlier = goal === "earlier";
  const available = earlier ? options.filter(c => c.earliest >= 0) : options;
  const value = c => earlier ? -c.earliest : c.delta.gain;
  const best = Math.max(...available.map(value));
  const improves = earlier ? currentTime === -1 || -currentTime < best : best > 0;
  const tied = improves ? available.filter(c => c.add.length && value(c) === best) : [];
  const startPoint = earlier ? study.points.find(p => minima(study,p,metric).length) : point;
  return {metric,current,qualifying: startPoint ? minima(study,startPoint,metric) : [],
    qualifyingCutoff:startPoint?.cutoffMs, options, best: minimal(tied.map(c=>c.add)),
    currentTime, bestTime: earlier && available.length ? -best : null};
}
function qualitativeAdvice(variation, current, goal, blocked, origins={}) {
  const evaluated = variation.claims.map(claim => {
    const groups = claim.requiresAny.filter(group => {
      const required=new Set(group);
      return (claim.distinctOrigins||[]).every(([a,b])=>!required.has(a)||!required.has(b)||
        (origins[a]&&origins[b]&&origins[a]!==origins[b]));
    });
    return {...claim, groups, known:groups.length>0, blockedByOrigin:claim.requiresAny.length>0&&!groups.length,
      satisfied:!blocked && groups.some(group => includesAll(current,group)),
      missing:minimal(groups.map(group => group.filter(id => !current.has(id))))};
  });
  const target = evaluated.filter(c=>c.goal===goal && c.known);
  const start = target.map(c=>({label:c.label,sets:smallest(c.groups),limit:c.qualification}));
  const next = blocked ? [] : target.filter(c=>!c.satisfied).map(c=>({label:c.label,sets:c.missing,limit:c.qualification}));
  return {evaluated, target, start, next};
}
function shapley(study, point, metric) {
  const sets = subsets(study.lenses);
  const denominator = observed(point,study.lenses.join(""),metric)?.[1];
  if (!denominator || sets.some(set => {
    const row=observed(point,mask(study,new Set(set)),metric);
    return !row || row[1]!==denominator || row[3]!==0;
  })) return null;
  function factorial(n) { return n ? n*factorial(n-1) : 1; }
  return Object.fromEntries(study.lenses.map(id => {
    const contributions = sets.filter(set=>!set.includes(id)).map(set => {
      const weight = factorial(set.length)*factorial(study.lenses.length-set.length-1) / factorial(study.lenses.length);
      const before = mask(study,new Set(set)), after = mask(study,new Set([...set,id]));
      return weight*difference(study,point,metric,before,after).gain;
    });
    return [id,contributions.reduce((total,x)=>total+x,0)];
  }));
}
function frontier(study, baseline, metric, estimates) {
  const missing = study.lenses.filter(id=>!baseline.has(id));
  if (!missing.every(id=>Object.hasOwn(estimates,id) && Number.isFinite(estimates[id]) && estimates[id]>=0)) return null;
  const rows = candidates(study,baseline,metric).map(row=>({...row,cost:row.add.reduce((total,id)=>total+estimates[id],0)}));
  return rows.filter(row=>!rows.some(other => other.cost<=row.cost && other.delta.gain>=row.delta.gain &&
    (other.cost<row.cost || other.delta.gain>row.delta.gain)));
}
function priorityAdvice(study, baseline, preferences) {
  const top = Math.max(0,...Object.values(preferences));
  if (!top) return null;
  const metrics=Object.keys(preferences).filter(metric=>preferences[metric]===top);
  const before=mask(study,baseline);
  const groups = subsets(study.lenses.filter(id=>!baseline.has(id)));
  const options=groups.map(add=>({
    add, gains:metrics.map(metric=>difference(study,finalPoint(study),metric,before,withAdd(study,baseline,add)))
  }));
  if (options.some(row=>row.gains.some(gain=>gain===null))) return {metrics,unknown:true};
  const admissible=options.filter(row=>row.gains.every(gain=>gain.falseChange<=0&&gain.after[3]===0));
  const topRows=admissible.filter(row=>!admissible.some(other=>other.gains.every((g,i)=>g.gain>=row.gains[i].gain)
    && other.gains.some((g,i)=>g.gain>row.gains[i].gain)));
  const concise=topRows.filter(row=>!topRows.some(other=>other.add.length<row.add.length &&
    includesAll(new Set(row.add),other.add) && other.gains.every((g,i)=>g.gain===row.gains[i].gain)));
  return {metrics, choices:concise};
}
export {goals,goalMetric,subsets,mask,minima,finalPoint,
    observed,qualifying,difference,earliest,measuredAdvice,qualitativeAdvice,shapley,frontier,priorityAdvice,withAdd};
