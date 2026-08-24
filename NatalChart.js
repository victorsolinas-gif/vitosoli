// ============================================================
// VITOSOLI - MODULE ASTRONOMIQUE (Carte astrale / Natal Chart)
// Implémentation basée sur les algorithmes de Jean Meeus
// Pas de dépendance externe - calculs purs JS
// ============================================================

const DEG2RAD = Math.PI / 180
const RAD2DEG = 180 / Math.PI

const ZODIAC_SIGNS = [
  'Bélier','Taureau','Gémeaux','Cancer','Lion','Vierge',
  'Balance','Scorpion','Sagittaire','Capricorne','Verseau','Poissons'
]

const PLANET_NAMES = {
  sun: 'Soleil', moon: 'Lune', mercury: 'Mercure', venus: 'Vénus',
  mars: 'Mars', jupiter: 'Jupiter', saturn: 'Saturne',
  uranus: 'Uranus', neptune: 'Neptune', pluto: 'Pluton'
}

// ── Normalisation d'angle 0-360 ──
function norm360(deg) {
  let d = deg % 360
  if (d < 0) d += 360
  return d
}

// ── Conversion date -> Jour Julien ──
function toJulianDay(year, month, day, hour, minute, second) {
  // month: 1-12
  let y = year, m = month
  if (m <= 2) { y -= 1; m += 12 }
  const A = Math.floor(y / 100)
  const B = 2 - A + Math.floor(A / 4)
  const dayFrac = day + (hour + minute / 60 + (second || 0) / 3600) / 24
  const JD = Math.floor(365.25 * (y + 4716)) + Math.floor(30.6001 * (m + 1)) + dayFrac + B - 1524.5
  return JD
}

// ── Siècles Juliens depuis J2000.0 ──
function julianCenturies(JD) {
  return (JD - 2451545.0) / 36525
}

// ── Obliquité de l'écliptique ──
function obliquity(T) {
  // IAU 2006 approximation (en degrés)
  const eps0 = 23.439291111 - 0.0130041667 * T - 0.00000016667 * T * T + 0.0000005036 * T * T * T
  return eps0
}

// ============================================================
// POSITION DU SOLEIL (precision ~0.01°)
// ============================================================
function sunPosition(T) {
  const L0 = norm360(280.46646 + 36000.76983 * T + 0.0003032 * T * T) // longitude moyenne
  const M = norm360(357.52911 + 35999.05029 * T - 0.0001537 * T * T)  // anomalie moyenne
  const Mrad = M * DEG2RAD

  const C = (1.914602 - 0.004817 * T - 0.000014 * T * T) * Math.sin(Mrad)
          + (0.019993 - 0.000101 * T) * Math.sin(2 * Mrad)
          + 0.000289 * Math.sin(3 * Mrad)

  const trueLong = norm360(L0 + C)
  return trueLong
}

// ============================================================
// POSITION DE LA LUNE (precision ~0.3°, Meeus simplifié)
// ============================================================
function moonPosition(T) {
  const Lp = norm360(218.3164477 + 481267.88123421 * T - 0.0015786 * T*T + T*T*T/538841 - T*T*T*T/65194000)
  const D  = norm360(297.8501921 + 445267.1114034 * T - 0.0018819 * T*T + T*T*T/545868 - T*T*T*T/113065000)
  const M  = norm360(357.5291092 + 35999.0502909 * T - 0.0001536 * T*T + T*T*T/24490000)
  const Mp = norm360(134.9633964 + 477198.8675055 * T + 0.0087414 * T*T + T*T*T/69699 - T*T*T*T/14712000)
  const F  = norm360(93.2720950 + 483202.0175233 * T - 0.0036539 * T*T - T*T*T/3526000 + T*T*T*T/863310000)

  const rad = DEG2RAD
  let lon = Lp
  // Principaux termes périodiques de longitude (degrés)
  lon += 6.288774 * Math.sin(Mp*rad)
  lon += 1.274027 * Math.sin((2*D - Mp)*rad)
  lon += 0.658314 * Math.sin(2*D*rad)
  lon += 0.213618 * Math.sin(2*Mp*rad)
  lon -= 0.185116 * Math.sin(M*rad)
  lon -= 0.114332 * Math.sin(2*F*rad)
  lon += 0.058793 * Math.sin((2*D - 2*Mp)*rad)
  lon += 0.057066 * Math.sin((2*D - M - Mp)*rad)
  lon += 0.053322 * Math.sin((2*D + Mp)*rad)
  lon += 0.045758 * Math.sin((2*D - M)*rad)
  lon -= 0.040923 * Math.sin((M - Mp)*rad)
  lon -= 0.034720 * Math.sin(D*rad)
  lon -= 0.030383 * Math.sin((M + Mp)*rad)
  lon += 0.015327 * Math.sin((2*D - 2*F)*rad)
  lon -= 0.012528 * Math.sin((Mp + 2*F)*rad)
  lon += 0.010980 * Math.sin((Mp - 2*F)*rad)
  lon += 0.010675 * Math.sin((4*D - Mp)*rad)
  lon += 0.010034 * Math.sin(3*Mp*rad)
  lon += 0.008548 * Math.sin((4*D - 2*Mp)*rad)

  return norm360(lon)
}

// ============================================================
// PLANETES (VSOP87 simplifie - termes principaux uniquement)
// Heliocentrique -> Geocentrique
// ============================================================

// Elements orbitaux moyens (a, e, i, L, lonPeri, lonNode) avec derivees /siecle
const ORBITAL_ELEMENTS = {
  mercury: { a:[0.38709927,0.00000037], e:[0.20563593,0.00001906], I:[7.00497902,-0.00594749],
             L:[252.25032350,149472.67411175], lonPeri:[77.45779628,0.16047689], lonNode:[48.33076593,-0.12534081] },
  venus:   { a:[0.72333566,0.00000390], e:[0.00677672,-0.00004107], I:[3.39467605,-0.00078890],
             L:[181.97909950,58517.81538729], lonPeri:[131.60246718,0.00268329], lonNode:[76.67984255,-0.27769418] },
  earth:   { a:[1.00000261,0.00000562], e:[0.01671123,-0.00004392], I:[-0.00001531,-0.01294668],
             L:[100.46457166,35999.37244981], lonPeri:[102.93768193,0.32327364], lonNode:[0,0] },
  mars:    { a:[1.52371034,0.00001847], e:[0.09339410,0.00007882], I:[1.84969142,-0.00813131],
             L:[-4.55343205,19140.30268499], lonPeri:[-23.94362959,0.44441088], lonNode:[49.55953891,-0.29257343] },
  jupiter: { a:[5.20288700,-0.00011607], e:[0.04838624,-0.00013253], I:[1.30439695,-0.00183714],
             L:[34.39644051,3034.74612775], lonPeri:[14.72847983,0.21252668], lonNode:[100.47390909,0.20469106] },
  saturn:  { a:[9.53667594,-0.00125060], e:[0.05386179,-0.00050991], I:[2.48599187,0.00193609],
             L:[49.95424423,1222.49362201], lonPeri:[92.59887831,-0.41897216], lonNode:[113.66242448,-0.28867794] },
  uranus:  { a:[19.18916464,-0.00196176], e:[0.04725744,-0.00004397], I:[0.77263783,-0.00242939],
             L:[313.23810451,428.48202785], lonPeri:[170.95427630,0.40805281], lonNode:[74.01692503,0.04240589] },
  neptune: { a:[30.06992276,0.00026291], e:[0.00859048,0.00005105], I:[1.77004347,0.00035372],
             L:[-55.12002969,218.45945325], lonPeri:[44.96476227,-0.32241464], lonNode:[131.78422574,-0.00508664] },
  pluto:   { a:[39.48211675,-0.00031596], e:[0.24882730,0.00005170], I:[17.14001206,0.00004818],
             L:[238.92903833,145.20780515], lonPeri:[224.06891629,-0.04062942], lonNode:[110.30393684,-0.01183482] }
}

function keplerSolve(M, e) {
  // Resolution iterative de l'equation de Kepler M = E - e*sin(E)
  let E = M
  for (let i = 0; i < 30; i++) {
    const dE = (E - e * Math.sin(E) - M) / (1 - e * Math.cos(E))
    E -= dE
    if (Math.abs(dE) < 1e-9) break
  }
  return E
}

// Calcule la position heliocentrique ecliptique (lon, lat, r) d'une planete
function heliocentricPosition(planet, T) {
  const el = ORBITAL_ELEMENTS[planet]
  const a = el.a[0] + el.a[1] * T
  const e = el.e[0] + el.e[1] * T
  const I = (el.I[0] + el.I[1] * T) * DEG2RAD
  const L = norm360(el.L[0] + el.L[1] * T) * DEG2RAD
  const lonPeri = (el.lonPeri[0] + el.lonPeri[1] * T) * DEG2RAD
  const lonNode = (el.lonNode[0] + el.lonNode[1] * T) * DEG2RAD

  const M = L - lonPeri // anomalie moyenne
  const E = keplerSolve(norm360(M * RAD2DEG) * DEG2RAD, e)

  // Coordonnees dans le plan orbital
  const xv = a * (Math.cos(E) - e)
  const yv = a * (Math.sqrt(1 - e*e) * Math.sin(E))
  const v = Math.atan2(yv, xv) // anomalie vraie
  const r = Math.sqrt(xv*xv + yv*yv)

  const argPeri = lonPeri - lonNode

  // Position dans l'espace (ecliptique heliocentrique)
  const xh = r * (Math.cos(lonNode) * Math.cos(argPeri + v) - Math.sin(lonNode) * Math.sin(argPeri + v) * Math.cos(I))
  const yh = r * (Math.sin(lonNode) * Math.cos(argPeri + v) + Math.cos(lonNode) * Math.sin(argPeri + v) * Math.cos(I))
  const zh = r * (Math.sin(argPeri + v) * Math.sin(I))

  return { x: xh, y: yh, z: zh, r }
}

// Convertit en geocentrique et retourne la longitude ecliptique apparente
function geocentricLongitude(planet, T) {
  const earth = heliocentricPosition('earth', T)
  const body = heliocentricPosition(planet, T)

  const xg = body.x - earth.x
  const yg = body.y - earth.y
  const zg = body.z - earth.z

  let lon = Math.atan2(yg, xg) * RAD2DEG
  return norm360(lon)
}

// ============================================================
// ASCENDANT ET MAISONS (systeme des maisons egales)
// ============================================================

// Temps sideral de Greenwich a 0h UT (en degres)
function greenwichSiderealTime(JD) {
  const T = julianCenturies(JD)
  let GST = 280.46061837 + 360.98564736629 * (JD - 2451545.0) + 0.000387933 * T*T - T*T*T / 38710000
  return norm360(GST)
}

// Calcule l'ascendant (degre ecliptique du point a l'horizon est)
function calculateAscendant(JD, latitude, longitude, obliquityDeg) {
  const LST = norm360(greenwichSiderealTime(JD) + longitude) // temps sideral local en degres
  const LSTrad = LST * DEG2RAD
  const lat = latitude * DEG2RAD
  const obl = obliquityDeg * DEG2RAD

  // Formule de l'ascendant
  const y = -Math.cos(LSTrad)
  const x = Math.sin(LSTrad) * Math.cos(obl) + Math.tan(lat) * Math.sin(obl)
  let asc = Math.atan2(y, x) * RAD2DEG
  return norm360(asc)
}

// Maison du Milieu du Ciel (MC)
function calculateMC(JD, longitude, obliquityDeg) {
  const LST = norm360(greenwichSiderealTime(JD) + longitude)
  const LSTrad = LST * DEG2RAD
  const obl = obliquityDeg * DEG2RAD
  let mc = Math.atan2(Math.sin(LSTrad), Math.cos(LSTrad) * Math.cos(obl)) * RAD2DEG
  return norm360(mc)
}

// Maisons egales (chaque maison = 30° a partir de l'Ascendant)
function calculateEqualHouses(ascendant) {
  const houses = []
  for (let i = 0; i < 12; i++) {
    houses.push(norm360(ascendant + i * 30))
  }
  return houses
}

// ============================================================
// SIGNES & DEGRES
// ============================================================
function longitudeToSign(lon) {
  const signIndex = Math.floor(lon / 30)
  const degree = lon % 30
  return {
    sign: ZODIAC_SIGNS[signIndex],
    signIndex,
    degree: Math.floor(degree),
    minute: Math.floor((degree % 1) * 60),
    longitude: lon
  }
}

// Determine dans quelle maison se trouve une longitude donnee
function findHouse(lon, houses) {
  for (let i = 0; i < 12; i++) {
    const start = houses[i]
    const end = houses[(i + 1) % 12]
    if (start < end) {
      if (lon >= start && lon < end) return i + 1
    } else {
      // wrap around 360
      if (lon >= start || lon < end) return i + 1
    }
  }
  return 1
}

// ============================================================
// ASPECTS
// ============================================================
const ASPECT_TYPES = [
  { name: 'Conjonction', angle: 0, orb: 8, symbol: '☌' },
  { name: 'Sextile', angle: 60, orb: 6, symbol: '⚹' },
  { name: 'Carré', angle: 90, orb: 8, symbol: '□' },
  { name: 'Trigone', angle: 120, orb: 8, symbol: '△' },
  { name: 'Opposition', angle: 180, orb: 8, symbol: '☍' }
]

function angleDiff(a, b) {
  let diff = Math.abs(a - b) % 360
  if (diff > 180) diff = 360 - diff
  return diff
}

function calculateAspects(planets) {
  const aspects = []
  const keys = Object.keys(planets)

  for (let i = 0; i < keys.length; i++) {
    for (let j = i + 1; j < keys.length; j++) {
      const p1 = keys[i], p2 = keys[j]
      const diff = angleDiff(planets[p1].longitude, planets[p2].longitude)

      for (const aspectType of ASPECT_TYPES) {
        const delta = Math.abs(diff - aspectType.angle)
        if (delta <= aspectType.orb) {
          aspects.push({
            planet1: p1,
            planet2: p2,
            type: aspectType.name,
            symbol: aspectType.symbol,
            angle: Math.round(diff * 10) / 10,
            orb: Math.round(delta * 10) / 10
          })
          break
        }
      }
    }
  }
  return aspects
}

// ============================================================
// FONCTION PRINCIPALE
// ============================================================
function calculateNatalChart({ year, month, day, hour, minute, latitude, longitude }) {
  // month: 1-12
  const JD = toJulianDay(year, month, day, hour, minute, 0)
  const T = julianCenturies(JD)
  const obl = obliquity(T)

  // Positions planetaires
  const planets = {}
  planets.sun = longitudeToSign(sunPosition(T))
  planets.moon = longitudeToSign(moonPosition(T))
  planets.mercury = longitudeToSign(geocentricLongitude('mercury', T))
  planets.venus = longitudeToSign(geocentricLongitude('venus', T))
  planets.mars = longitudeToSign(geocentricLongitude('mars', T))
  planets.jupiter = longitudeToSign(geocentricLongitude('jupiter', T))
  planets.saturn = longitudeToSign(geocentricLongitude('saturn', T))
  planets.uranus = longitudeToSign(geocentricLongitude('uranus', T))
  planets.neptune = longitudeToSign(geocentricLongitude('neptune', T))
  planets.pluto = longitudeToSign(geocentricLongitude('pluto', T))

  // Ascendant et maisons
  const ascendant = calculateAscendant(JD, latitude, longitude, obl)
  const mc = calculateMC(JD, longitude, obl)
  const houseCusps = calculateEqualHouses(ascendant)

  // Maison de chaque planete
  for (const key of Object.keys(planets)) {
    planets[key].house = findHouse(planets[key].longitude, houseCusps)
    planets[key].name = PLANET_NAMES[key]
  }

  const ascendantSign = longitudeToSign(ascendant)
  const mcSign = longitudeToSign(mc)

  // Aspects
  const aspects = calculateAspects(planets)

  // Maisons formatees
  const houses = houseCusps.map((cusp, i) => ({
    number: i + 1,
    ...longitudeToSign(cusp)
  }))

  return {
    planets,
    ascendant: { ...ascendantSign, name: 'Ascendant' },
    midheaven: { ...mcSign, name: 'Milieu du Ciel' },
    houses,
    aspects,
    julianDay: JD
  }
}

export { calculateNatalChart, ZODIAC_SIGNS, PLANET_NAMES }
