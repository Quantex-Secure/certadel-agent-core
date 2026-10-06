# Certadel brand

The mark is a **shield with a crenellated (castle-battlement) top and a check inside** —
*certificate* + *citadel*: a fortress that vouches your certs are valid.

## Files
| File | Use |
| --- | --- |
| `certadel-mark.svg` | Icon only (square). App icon, favicon, social avatar. |
| `certadel-logo.svg` | Mark + "Certadel" wordmark (horizontal lockup). |

The agent and UCM ship `certadel-mark.svg` as their favicon (`wwwroot/favicon.svg`).

## Colours
| Token | Hex | Where |
| --- | --- | --- |
| Brand blue (light) | `#5C7CFA` | gradient top |
| Brand blue (dark) | `#3B5BDB` | gradient bottom |
| Check / knockout | `#FFFFFF` | the checkmark |

To recolour, edit the two `stop-color` values in the gradient. The wordmark text in
`certadel-logo.svg` uses `currentColor`, so it adapts to a light or dark background
(set `color:` on the parent, or change `fill` to a fixed value).

## Naming
- Suite: **Certadel**
- Per-server service + web UI: **Certadel Agent**
- Fleet console (desktop): **Certadel UCM**

Conflict-checked (2026-06): no certificate-software product/repo/company and no USPTO
mark for "Certadel". Register `certadel.com` (+ `.io`/`.dev`) before public launch.
