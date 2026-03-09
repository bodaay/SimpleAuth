# X.Green Brand Guidelines

> **Purpose:** This document is the single source of truth for all visual and UI decisions across X.Green products. Any agent, designer, or developer implementing UI must follow these guidelines exactly. No improvisation. No "close enough."

---

## 1. Brand Identity

**Brand Name:** X.Green
**Tone:** Premium, institutional, warm, refined. Think sovereign wealth — not startup.
**Cultural Influence:** Middle Eastern elegance. Earthy warmth. Gold as a prestige signal.
**Typography Feel:** Clean, modern, high-contrast hierarchy.

---

## 2. Color System

### 2.1 Master Palette

Every color below is an official brand color. Each has a **semantic role** that defines when and how it is used.

| Token Name            | Hex       | RGB             | Pantone       | Role                                      |
|-----------------------|-----------|-----------------|---------------|--------------------------------------------|
| `warm-gray`           | `#D6D1CA` | 214, 209, 202   | Warm Gray 1C  | Light backgrounds, subtle fills            |
| `slate`               | `#333F48` | 51, 63, 72      | 432C          | Primary text (light mode), dark surfaces   |
| `burgundy`            | `#8B153D` | 139, 21, 61     | 1955C         | Hero accent, CTAs, brand punch             |
| `sage`                | `#A59F8A` | 165, 159, 138   | 7536C         | Secondary/muted UI, dividers, tags         |
| `copper`              | `#B87132` | 184, 113, 50    | 7572C         | Warm accent, icons, highlights             |
| `mauve`               | `#C1A18D` | 193, 161, 141   | 4044C         | Soft accent, cards, secondary backgrounds  |
| `black`               | `#000000` | 0, 0, 0         | Black 6C      | True black — use sparingly, high contrast  |
| `gold-light`          | `#F8E08E` | 248, 224, 142   | 1205C         | Gold gradient start, highlight, badge fill |
| `gold-dark`           | `#8F6A2A` | 143, 106, 42    | 7559C         | Gold gradient end, premium text accents    |
| `cool-gray`           | `#5B6770` | 91, 103, 112    | 431C          | Secondary text, metadata, captions         |

### 2.2 Gold Gradient

The signature brand gradient. Used for premium accents, badges, progress bars, and decorative elements.

```
Direction:  left to right (90deg) or top to bottom (180deg)
Start:      #F8E08E (gold-light)
End:        #8F6A2A (gold-dark)
```

**CSS:**
```css
background: linear-gradient(90deg, #F8E08E 0%, #8F6A2A 100%);
```

**Usage rules:**
- NEVER use the gradient on large surface areas (backgrounds, full cards).
- USE for: thin accent bars, badges, premium labels, progress indicators, decorative lines, icon fills.
- The gradient always flows from light-to-dark (never reversed).

---

## 3. Light Theme

### 3.1 Surfaces & Backgrounds

| Element                  | Token                | Value                |
|--------------------------|----------------------|----------------------|
| Page background          | `--bg-page`          | `#FAFAF8`            |
| Card / panel background  | `--bg-card`          | `#FFFFFF`            |
| Sidebar / nav background | `--bg-sidebar`       | `#F3F1ED`            |
| Hover / subtle fill      | `--bg-hover`         | `#EDEAE5`            |
| Active / selected fill   | `--bg-active`        | `#E5E1DA`            |
| Elevated surface         | `--bg-elevated`      | `#FFFFFF`            |
| Overlay / backdrop       | `--bg-overlay`       | `rgba(51,63,72,0.5)` |

### 3.2 Text

| Element                  | Token                | Value                |
|--------------------------|----------------------|----------------------|
| Primary text             | `--text-primary`     | `#333F48`            |
| Secondary text           | `--text-secondary`   | `#5B6770`            |
| Muted / caption          | `--text-muted`       | `#A59F8A`            |
| Inverse text (on dark)   | `--text-inverse`     | `#FAFAF8`            |
| Link text                | `--text-link`        | `#8B153D`            |
| Link hover               | `--text-link-hover`  | `#6E1030`            |

### 3.3 Borders & Dividers

| Element                  | Token                | Value                |
|--------------------------|----------------------|----------------------|
| Default border           | `--border-default`   | `#D6D1CA`            |
| Subtle border            | `--border-subtle`    | `#EDEAE5`            |
| Strong border            | `--border-strong`    | `#A59F8A`            |
| Focus ring               | `--border-focus`     | `#8B153D`            |

### 3.4 Interactive Elements

| Element                  | Token                   | Value                |
|--------------------------|-------------------------|----------------------|
| Primary button bg        | `--btn-primary-bg`      | `#8B153D`            |
| Primary button text      | `--btn-primary-text`    | `#FFFFFF`            |
| Primary button hover     | `--btn-primary-hover`   | `#6E1030`            |
| Secondary button bg      | `--btn-secondary-bg`    | `transparent`        |
| Secondary button border  | `--btn-secondary-border`| `#333F48`            |
| Secondary button text    | `--btn-secondary-text`  | `#333F48`            |
| Secondary button hover   | `--btn-secondary-hover` | `#F3F1ED`            |
| Accent button bg         | `--btn-accent-bg`       | `linear-gradient(90deg, #F8E08E, #8F6A2A)` |
| Accent button text       | `--btn-accent-text`     | `#333F48`            |
| Disabled bg              | `--btn-disabled-bg`     | `#EDEAE5`            |
| Disabled text            | `--btn-disabled-text`   | `#A59F8A`            |

### 3.5 Semantic / Status Colors

| Status     | Background     | Text / Icon    | Border         |
|------------|----------------|----------------|----------------|
| Success    | `#E8F0E4`      | `#3A6B35`      | `#3A6B35`      |
| Warning    | `#FDF4E0`      | `#8F6A2A`      | `#B87132`      |
| Error      | `#F8E4E4`      | `#8B153D`      | `#8B153D`      |
| Info       | `#E4EBF0`      | `#333F48`      | `#5B6770`      |

> Note: Semantic colors are intentionally derived from the brand palette (burgundy for error, copper/gold for warning) to maintain brand consistency.

---

## 4. Dark Theme

### 4.1 Surfaces & Backgrounds

| Element                  | Token                | Value                |
|--------------------------|----------------------|----------------------|
| Page background          | `--bg-page`          | `#1A1E22`            |
| Card / panel background  | `--bg-card`          | `#242A30`            |
| Sidebar / nav background | `--bg-sidebar`       | `#1E2328`            |
| Hover / subtle fill      | `--bg-hover`         | `#2C333A`            |
| Active / selected fill   | `--bg-active`        | `#343C44`            |
| Elevated surface         | `--bg-elevated`      | `#2A3138`            |
| Overlay / backdrop       | `--bg-overlay`       | `rgba(0,0,0,0.6)`   |

### 4.2 Text

| Element                  | Token                | Value                |
|--------------------------|----------------------|----------------------|
| Primary text             | `--text-primary`     | `#E8E4DE`            |
| Secondary text           | `--text-secondary`   | `#A59F8A`            |
| Muted / caption          | `--text-muted`       | `#6B6760`            |
| Inverse text (on light)  | `--text-inverse`     | `#1A1E22`            |
| Link text                | `--text-link`        | `#D4A0A0`            |
| Link hover               | `--text-link-hover`  | `#E0B5B5`            |

> Note: In dark mode, burgundy is too dark to read on dark surfaces. Links use a **softened rose** derived from burgundy to maintain brand association while ensuring readability (WCAG AA minimum).

### 4.3 Borders & Dividers

| Element                  | Token                | Value                |
|--------------------------|----------------------|----------------------|
| Default border           | `--border-default`   | `#3A424A`            |
| Subtle border            | `--border-subtle`    | `#2C333A`            |
| Strong border            | `--border-strong`    | `#5B6770`            |
| Focus ring               | `--border-focus`     | `#D4A0A0`            |

### 4.4 Interactive Elements

| Element                  | Token                   | Value                |
|--------------------------|-------------------------|----------------------|
| Primary button bg        | `--btn-primary-bg`      | `#A02050`            |
| Primary button text      | `--btn-primary-text`    | `#FFFFFF`            |
| Primary button hover     | `--btn-primary-hover`   | `#B82D60`            |
| Secondary button bg      | `--btn-secondary-bg`    | `transparent`        |
| Secondary button border  | `--btn-secondary-border`| `#E8E4DE`            |
| Secondary button text    | `--btn-secondary-text`  | `#E8E4DE`            |
| Secondary button hover   | `--btn-secondary-hover` | `#2C333A`            |
| Accent button bg         | `--btn-accent-bg`       | `linear-gradient(90deg, #F8E08E, #8F6A2A)` |
| Accent button text       | `--btn-accent-text`     | `#1A1E22`            |
| Disabled bg              | `--btn-disabled-bg`     | `#2C333A`            |
| Disabled text            | `--btn-disabled-text`   | `#5B6770`            |

> Note: In dark mode, the primary burgundy button is **lightened** to `#A02050` so it remains visible against dark surfaces. The gold gradient stays the same — it has enough luminance to work on both themes.

### 4.5 Semantic / Status Colors (Dark)

| Status     | Background          | Text / Icon    | Border         |
|------------|---------------------|----------------|----------------|
| Success    | `rgba(58,107,53,0.2)`  | `#7DB877`   | `#5A9B54`      |
| Warning    | `rgba(184,113,50,0.2)` | `#D4A96A`   | `#B87132`      |
| Error      | `rgba(139,21,61,0.2)`  | `#D4A0A0`   | `#A02050`      |
| Info       | `rgba(91,103,112,0.2)` | `#A0B0BC`   | `#5B6770`      |

---

## 5. Typography Guidelines

### 5.1 Scale

Use a consistent type scale across all products. Sizes in `rem` (base = 16px).

| Level          | Size     | Weight   | Line Height | Letter Spacing | Usage                        |
|----------------|----------|----------|-------------|----------------|------------------------------|
| Display        | `2.5rem` | 700      | 1.1         | `-0.02em`      | Hero sections, landing pages |
| H1             | `2rem`   | 700      | 1.2         | `-0.015em`     | Page titles                  |
| H2             | `1.5rem` | 600      | 1.25        | `-0.01em`      | Section headers              |
| H3             | `1.25rem`| 600      | 1.3         | `0`            | Card titles, sub-sections    |
| H4             | `1rem`   | 600      | 1.4         | `0`            | Labels, small headers        |
| Body           | `1rem`   | 400      | 1.6         | `0`            | Default paragraph text       |
| Body Small     | `0.875rem`| 400     | 1.5         | `0`            | Secondary content            |
| Caption        | `0.75rem`| 400      | 1.4         | `0.02em`       | Metadata, timestamps, hints  |
| Overline       | `0.75rem`| 600      | 1.4         | `0.08em`       | Category labels (uppercase)  |

### 5.2 Font Stack

```css
--font-primary: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
--font-arabic: 'IBM Plex Sans Arabic', 'Noto Sans Arabic', sans-serif;
--font-mono: 'JetBrains Mono', 'Fira Code', monospace;
```

> When Arabic content is detected, switch to `--font-arabic`. Never mix Arabic and Latin typefaces in the same text block.

---

## 6. Spacing & Layout

### 6.1 Spacing Scale

Base unit: `4px`. All spacing must be a multiple of 4.

| Token    | Value   | Usage                              |
|----------|---------|-------------------------------------|
| `--sp-1` | `4px`   | Tight inline spacing               |
| `--sp-2` | `8px`   | Icon-to-text gap, tight padding    |
| `--sp-3` | `12px`  | Small component padding            |
| `--sp-4` | `16px`  | Default component padding          |
| `--sp-5` | `20px`  | Medium gaps                        |
| `--sp-6` | `24px`  | Card padding, section gaps         |
| `--sp-8` | `32px`  | Large section padding              |
| `--sp-10`| `40px`  | Page margins, major sections       |
| `--sp-12`| `48px`  | Hero spacing                       |
| `--sp-16`| `64px`  | Page-level vertical rhythm         |

### 6.2 Border Radius

| Token             | Value   | Usage                              |
|-------------------|---------|-------------------------------------|
| `--radius-sm`     | `4px`   | Tags, chips, small elements        |
| `--radius-md`     | `8px`   | Buttons, inputs, cards             |
| `--radius-lg`     | `12px`  | Modals, panels, large cards        |
| `--radius-xl`     | `16px`  | Feature cards, hero elements       |
| `--radius-full`   | `9999px`| Avatars, pills, circular elements  |

---

## 7. Shadows & Elevation

### 7.1 Light Theme Shadows

```css
--shadow-sm:  0 1px 2px rgba(51, 63, 72, 0.06);
--shadow-md:  0 2px 8px rgba(51, 63, 72, 0.08);
--shadow-lg:  0 4px 16px rgba(51, 63, 72, 0.10);
--shadow-xl:  0 8px 32px rgba(51, 63, 72, 0.12);
```

### 7.2 Dark Theme Shadows

```css
--shadow-sm:  0 1px 2px rgba(0, 0, 0, 0.2);
--shadow-md:  0 2px 8px rgba(0, 0, 0, 0.25);
--shadow-lg:  0 4px 16px rgba(0, 0, 0, 0.3);
--shadow-xl:  0 8px 32px rgba(0, 0, 0, 0.4);
```

---

## 8. Component Patterns

### 8.1 Cards

- Background: `--bg-card`
- Border: `1px solid var(--border-default)`
- Border radius: `--radius-lg`
- Padding: `--sp-6`
- Shadow: `--shadow-sm` at rest, `--shadow-md` on hover
- Transition: `all 0.2s ease`

### 8.2 Inputs & Form Fields

- Background: `--bg-card`
- Border: `1px solid var(--border-default)`
- Border radius: `--radius-md`
- Padding: `--sp-3` vertical, `--sp-4` horizontal
- Focus: border changes to `--border-focus`, add `0 0 0 3px rgba(139,21,61,0.15)` ring (light) or `0 0 0 3px rgba(212,160,160,0.2)` ring (dark)
- Placeholder text: `--text-muted`

### 8.3 Buttons

- Border radius: `--radius-md`
- Padding: `--sp-3` vertical, `--sp-6` horizontal
- Font weight: 600
- Font size: Body (1rem) for default, Body Small (0.875rem) for compact
- Transition: `all 0.15s ease`
- NEVER use pure black or pure white buttons. Always use themed tokens.

### 8.4 Navigation / Sidebar

- Background: `--bg-sidebar`
- Active item: `--bg-active` background with `--text-primary` text and a `3px` left border in burgundy (`#8B153D` light / `#A02050` dark)
- Hover: `--bg-hover`
- Icons: `--text-secondary`, active: `--text-primary`

### 8.5 Badges / Tags

- Default: `--bg-hover` background, `--text-secondary` text
- Premium/Gold: Gold gradient background, `--slate` text (light) or `--bg-page` text (dark)
- Status: Use semantic color system (see Section 3.5 / 4.5)
- Border radius: `--radius-sm`
- Font size: Caption
- Font weight: 600
- Padding: `--sp-1` vertical, `--sp-2` horizontal

---

## 9. Iconography

- Style: Outlined (1.5px stroke), rounded caps and joins
- Default size: `20px` (body context), `24px` (nav/header), `16px` (compact/table)
- Color: inherits text color via `currentColor`
- Recommended library: Lucide Icons (consistent with outlined style)
- NEVER use filled icons for navigation. Reserve filled variants for "active/selected" states only.

---

## 10. Motion & Animation

| Property          | Duration  | Easing                     | Usage                    |
|-------------------|-----------|----------------------------|--------------------------|
| Color transitions | `150ms`   | `ease`                     | Hovers, focus states     |
| Layout shifts     | `200ms`   | `ease-in-out`              | Expanding, collapsing    |
| Entrances         | `250ms`   | `cubic-bezier(0,0,0.2,1)` | Modals, dropdowns, toast |
| Exits             | `150ms`   | `cubic-bezier(0.4,0,1,1)` | Closing, dismissing      |

**Rules:**
- NEVER animate layout properties (width, height, top, left). Use `transform` and `opacity`.
- Respect `prefers-reduced-motion`. When active, set all durations to `0ms`.

---

## 11. Accessibility Requirements

- All text must meet **WCAG AA** contrast ratio (4.5:1 for body, 3:1 for large text).
- Focus indicators must be visible in both themes (burgundy ring light, rose ring dark).
- Interactive elements must have a minimum touch target of `44px x 44px`.
- Never rely on color alone to convey meaning — pair with icons or text labels.
- All images require meaningful `alt` text.
- Support `prefers-color-scheme` for automatic theme switching.
- Support `prefers-reduced-motion` for animation control.

---

## 12. Do's and Don'ts

### DO:
- Use the burgundy as your primary accent — it's the brand's signature.
- Use the gold gradient for premium/VIP/highlight moments.
- Keep backgrounds warm (warm grays, not cool grays) in light mode.
- Maintain generous whitespace — the brand feels premium through breathing room.
- Use the slate (`#333F48`) as your primary dark — it's softer than pure black.

### DON'T:
- Don't use pure black (`#000000`) for text or large surfaces — use slate instead.
- Don't invent new colors. Every color must trace back to this palette.
- Don't use the gold gradient on backgrounds or large areas — it's an accent only.
- Don't mix warm and cool grays in the same view.
- Don't reduce spacing to cram more content. If it doesn't fit, redesign the layout.
- Don't use low-opacity text as a substitute for the muted color tokens.

---

## 13. CSS Custom Properties Reference

See the companion file `tokens.css` for copy-paste-ready CSS custom properties for both themes.
