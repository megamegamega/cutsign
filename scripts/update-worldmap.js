// Refresh lib/worldmap.json: Natural Earth 1:110m country outlines (via world-atlas, pinned),
// projected once here with Equal Earth into SVG path strings, so the Actors tab draws its map with
// no runtime dependency and no network. Antarctica is dropped. Run only to change the projection
// or the source edition; the result is committed.
//   npm run update-worldmap [-- path/to/countries-110m.json]

import { readFileSync, writeFileSync } from 'node:fs';

const SOURCE = 'https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json';
const topo = process.argv[2]
  ? JSON.parse(readFileSync(process.argv[2], 'utf8'))
  : await (await fetch(SOURCE)).json();

// TopoJSON arcs are quantized and delta-encoded; decode each to [lon, lat] points
const { scale: [sx, sy], translate: [tx, ty] } = topo.transform;
const arcs = topo.arcs.map((arc) => {
  let x = 0; let y = 0;
  return arc.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; });
});
// a ring is a list of arc indices; ~i means arc i reversed; consecutive arcs share an endpoint
const ring = (idx) => idx.flatMap((i, k) => {
  const pts = i < 0 ? [...arcs[~i]].reverse() : arcs[i];
  return k ? pts.slice(1) : pts;
});

// Equal Earth (Šavrič, Patterson & Jenny 2018), in radians
const A1 = 1.340264; const A2 = -0.081106; const A3 = 0.000893; const A4 = 0.003796; const M = Math.sqrt(3) / 2;
const equalEarth = ([lon, lat]) => {
  const l = lon * Math.PI / 180; const t = Math.asin(M * Math.sin(lat * Math.PI / 180));
  const t2 = t * t; const t6 = t2 * t2 * t2;
  return [l * Math.cos(t) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2))), t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))];
};

// The source is spherical: a ring crossing the antimeridian (Russia, Fiji) jumps from +180 to -180.
// Unwrap each such polygon so its longitudes run on past ±180, then draw it twice, once shifted a
// full turn; the page clips both to the globe's outline, which leaves each half on its own edge.
const unwrap = (r) => {
  const out = [r[0].slice()];
  for (let i = 1; i < r.length; i++) {
    let lon = r[i][0];
    while (lon - out[i - 1][0] > 180) lon -= 360;
    while (lon - out[i - 1][0] < -180) lon += 360;
    out.push([lon, r[i][1]]);
  }
  return out;
};
const shifted = (poly, by) => poly.map((r) => r.map(([lon, lat]) => [lon + by, lat]));
const polysOf = (g) => (g.type === 'Polygon' ? [g.arcs] : g.arcs).flatMap((p) => {
  const poly = p.map((r) => unwrap(ring(r)));
  const lons = poly.flat().map((q) => q[0]);
  return [poly, ...(Math.max(...lons) > 180 ? [shifted(poly, -360)] : []), ...(Math.min(...lons) < -180 ? [shifted(poly, 360)] : [])];
});
const geoms = topo.objects.countries.geometries.filter((g) => g.id !== '010' && g.arcs); // no Antarctica
const projected = geoms.map((g) => ({ g, polys: polysOf(g).map((poly) => poly.map((r) => r.map(equalEarth))) }));

// the globe's edge (the ±180° meridians) is the clip outline and sets the width; the land sets the height
const edge = [...Array.from({ length: 91 }, (_, i) => [-180, -90 + 2 * i]), ...Array.from({ length: 91 }, (_, i) => [180, 90 - 2 * i])].map(equalEarth);
const land = projected.flatMap((p) => p.polys.flat(2));
const [x0, x1] = [Math.min(...edge.map((p) => p[0])), Math.max(...edge.map((p) => p[0]))];
const [y0, y1] = [Math.min(...land.map((p) => p[1])), Math.max(...land.map((p) => p[1]))];
const W = 1000; const k = W / (x1 - x0); const H = Math.ceil((y1 - y0) * k);
const px = ([x, y]) => [(x - x0) * k, (y1 - y) * k];
const r1 = (v) => Math.round(v * 10) / 10;

// relative moves keep the file small; rings with under 3 distinct points at this precision drop
const pathOf = (rings) => rings.map((r) => {
  const pts = r.map(px).map(([x, y]) => [r1(x), r1(y)]).filter((p, i, a) => !i || p[0] !== a[i - 1][0] || p[1] !== a[i - 1][1]);
  if (pts.length < 3) return '';
  let [cx, cy] = pts[0];
  let d = `M${cx},${cy}l`;
  for (const [x, y] of pts.slice(1)) { d += `${r1(x - cx)},${r1(y - cy)} `; cx = x; cy = y; }
  return d.trim() + 'z';
}).join('');
// label anchor: the centre of the largest polygon's bounding box, among those centred on the map
// (a shifted copy of Russia shares the original's area but sits off the left edge)
const anchor = (p) => {
  const box = (r) => { const xs = r.map((q) => q[0]); const ys = r.map((q) => q[1]); return [(Math.min(...xs) + Math.max(...xs)) / 2, (Math.min(...ys) + Math.max(...ys)) / 2]; };
  const big = p.polys.map((poly) => poly[0].map(px)).filter((r) => { const [cx] = box(r); return cx >= 0 && cx <= W; }).sort((a, b) => area(b) - area(a))[0];
  return box(big).map(r1);
};
const area = (pts) => Math.abs(pts.reduce((s, [x, y], i) => { const [nx, ny] = pts[(i + 1) % pts.length]; return s + x * ny - nx * y; }, 0) / 2);

const countries = projected.map((p) => ({ id: p.g.id || null, name: p.g.properties.name, c: anchor(p), d: p.polys.map(pathOf).join('') }))
  .filter((c) => c.d);
writeFileSync(new URL('../lib/worldmap.json', import.meta.url), JSON.stringify({
  source: 'Natural Earth 1:110m (public domain) via world-atlas@2.0.2 (ISC)', projection: 'Equal Earth', viewBox: `0 0 ${W} ${H}`,
  outline: pathOf([edge]), countries,
}) + '\n');
console.log(`worldmap: ${countries.length} countries, ${W}x${H}`);
