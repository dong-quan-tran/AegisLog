const BASE_URL = '/api'

async function postJson(path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })

  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch (e) {
    // keep raw text if JSON parse fails
    data = text
  }

  if (!res.ok) {
    const detail =
      data && data.detail
        ? typeof data.detail === 'string'
          ? data.detail
          : JSON.stringify(data.detail)
        : res.statusText
    throw new Error(`Request failed (${res.status}): ${detail}`)
  }

  return data
}

export async function apiNormalize(payload) {
  return postJson('/normalize', payload)
}

export async function apiNormalizedIncidents(payload) {
  return postJson('/normalized-incidents', payload)
}

export async function apiNormalizedExplain(payload) {
  return postJson('/normalized-explain', payload)
}