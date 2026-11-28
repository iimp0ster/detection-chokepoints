import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import * as model from "../assets/js/telemetry-value-model.mjs";
import {projectStudy} from "../assets/js/telemetry-value-study.mjs";

function load(path) {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
}

const dataset = load("../assets/data/detection-lens-explorer.v1.json");
const profile = load("../assets/data/telemetry-value/container-escape-variations.v1.json");
const {studySelection} = profile;
const projection = projectStudy(dataset, studySelection);
const final = model.finalPoint(projection);

test("the adapter preserves 256 exact replay rows, four cutoffs and 16 reviewed minima", () => {
  assert.deepEqual(projection.points.map(point=>point.cutoffMs), [250,1000,5000,null]);
  const study = dataset.studies.find(item=>item.id===studySelection.study);
  for (const point of projection.points) {
    const source = study.groups.find(item=>item.profile==="augmented" && item.cutoff===point.cutoffMs);
    assert.equal(Object.keys(point.rows).length, 64);
    for (const [mask, row] of Object.entries(point.rows)) {
      const [cohorts] = source.rows[mask];
      for (const [claim, counts] of Object.entries(row)) {
        assert.deepEqual(counts, cohorts["path/workload_delegated"][claim]);
      }
    }
    for (const claim of Object.keys(projection.metrics)) {
      assert.deepEqual(model.minima(projection,point,claim).map(set=>set.join("")).sort(),
        [...source.minimum["path/workload_delegated"][claim]].sort());
    }
  }
  assert.throws(()=>projectStudy(dataset,{...studySelection,revision:"unapproved"}));
});

test("causal reconstruction needs W and A together while downstream effects stay saturated", () => {
  assert.deepEqual(final.rows.DH.effect, [9,9,0,0]);
  assert.deepEqual(final.rows.DH.causal, [0,7,11,0]);
  assert.deepEqual(final.rows.WDAH.causal, [7,7,4,0]);
  assert.equal(model.difference(projection,final,"effect","DH","WDAH").gain, 0);
  for (const mask of ["WDH","DAH"]) {
    assert.equal(model.difference(projection,final,"causal","DH",mask).gain, 0);
  }
  assert.deepEqual(model.measuredAdvice(projection,new Set("DH"),"causal").best, [["W","A"]]);
  assert.deepEqual(model.measuredAdvice(projection,new Set("DH"),"effect").best, []);
  assert.equal(model.measuredAdvice(projection,new Set("DH"),"earlier").bestTime, 2);
  assert.equal(model.measuredAdvice(projection,new Set("DH"),"attribution"), null);
});

test("Shapley requires complete comparable replay data and retains scoped contributions", () => {
  for (const [metric, expected] of [
    ["effect",{P:0,W:0,K:0,D:4.5,A:0,H:4.5}],
    ["causal",{P:0,W:1.75,K:0,D:1.75,A:1.75,H:1.75}]
  ]) {
    const actual=model.shapley(projection,final,metric);
    for (const lens of projection.lenses) assert.ok(Math.abs(actual[lens]-expected[lens])<1e-8);
  }
  const changed=structuredClone(projection);
  delete model.finalPoint(changed).rows.WH;
  assert.equal(model.shapley(changed,model.finalPoint(changed),"effect"),null);
  assert.equal(model.difference(changed,model.finalPoint(changed),"effect","WH","WDAH"),null);
  model.finalPoint(changed).rows.DH.effect={status:"conflicting",reason:"duplicate origin"};
  assert.equal(model.difference(changed,model.finalPoint(changed),"effect","DH","WDAH"),null);
});

test("effort and leading priorities require explicit inputs", () => {
  const baseline=new Set("DH");
  assert.equal(model.frontier(projection,baseline,"causal",{W:2}),null);
  const options=model.frontier(projection,baseline,"causal",{W:2,A:3,P:1,K:1});
  assert.deepEqual(options.map(item=>[item.add.join(""),item.cost,item.delta.gain]),[["",0,0],["WA",5,7]]);
  assert.deepEqual(model.priorityAdvice(projection,baseline,{effect:4,causal:1}).choices.map(x=>x.add),[[]]);
  assert.deepEqual(model.priorityAdvice(projection,baseline,{effect:1,causal:4}).choices.map(x=>x.add),[["W","A"]]);
});

test("qualitative claims preserve declared origin constraints and unresolved disputes", () => {
  const variant={claims:[{label:"Joint claim",requiresAny:[["a","b"],["c","d"]],
    distinctOrigins:[["a","b"]],goal:"effect"}]};
  const origins={a:"same",b:"same",c:"left",d:"right"};
  const derived=model.qualitativeAdvice(variant,new Set("ab"),"effect",false,origins);
  assert.equal(derived.evaluated[0].satisfied,false);
  assert.deepEqual(derived.next[0].sets,[["c","d"]]);
  assert.equal(model.qualitativeAdvice(variant,new Set("cd"),"effect",true).evaluated[0].satisfied,false);
});

