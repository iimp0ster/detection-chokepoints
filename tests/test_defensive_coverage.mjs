import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {approvedRoute, missingEvidence, sitePath, validProfile} from '../assets/js/defensive-coverage.mjs';
import {availableRoutes, minimumCuts, studyProfile} from '../assets/js/container-escape-explorer.mjs';

const load = (file) => JSON.parse(readFileSync(new URL('../'+file, import.meta.url), 'utf8'));
const data = load('assets/data/defensive-coverage/container-escape-variations.v1.json');
const graph = load('assets/data/container-escape-research.v1.json');

test('evidence alternatives are OR between complete groups and AND within one group', () => {
  const alternatives = [['job', 'dest'], ['proc', 'file', 'dest']];
  assert.deepEqual(missingEvidence(alternatives,new Set(['job'])), ['dest']);
  assert.deepEqual(missingEvidence(alternatives,new Set(['dest','proc','file'])), []);
  assert.deepEqual(missingEvidence(alternatives,new Set(['proc','dest'])), ['job']);
  assert.equal(missingEvidence([],new Set(['job','dest'])), null);
});

test('runtime loading accepts source-only profiles and confines routes', () => {
  const {behavioralGraph, evidenceExamples, findings, placements, ...sourceOnly} = data;
  assert.equal(validProfile(sourceOnly), true);
  assert.equal(validProfile({...data, schemaVersion:'2.0.0'}), false);
  assert.equal(validProfile({...data, behavioralGraph:{...behavioralGraph,path:'//other/graph.json'}}), false);
  assert.equal(validProfile({...data, references:[{url:'javascript:alert(1)'}]}), false);
  assert.equal(sitePath(data.behavioralGraph.explorer, '/detection-chokepoints'), '/detection-chokepoints/lens-explorer/container-escape/');
});

test('switching sources leaves every approved route unchanged', () => {
  const original = JSON.stringify(graph);
  for (const variation of data.variations) {
    const route = variation.graph && approvedRoute(graph,variation.graph.objective,variation.graph.route);
    if (variation.graph) assert.ok(route);
    for (const preset of data.presets) {
      for (const claim of variation.claims) missingEvidence(claim.requiresAny,new Set(preset.sources));
      if (variation.graph) assert.equal(approvedRoute(graph,variation.graph.objective,variation.graph.route), route);
    }
  }
  assert.equal(JSON.stringify(graph), original);
});

test('container Explorer adapter preserves all independently reviewed cuts', () => {
  const canon = (sets) => sets.map((set)=>JSON.stringify([...set].sort())).sort();
  const profile = studyProfile(graph);
  for (const example of graph.validationCases) {
    const routes = availableRoutes(profile[example.objective],99,new Set(example.activeFacts));
    const actual = minimumCuts(routes,new Set(example.ineligibleControls));
    assert.deepEqual(canon(actual),canon(example.minimumCuts),example.id);
  }
});

