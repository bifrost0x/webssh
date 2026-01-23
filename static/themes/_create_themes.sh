#!/bin/bash

# Create 15 professional theme presets

themes=(
  "midnight-azure:#1e3a8a:Deep blues inspired by midnight sky:cool"
  "forest-canopy:#166534:Rich greens of a lush forest:nature"
  "sunset-blaze:#ea580c:Warm oranges of a brilliant sunset:warm"
  "arctic-ice:#0891b2:Cool teals reminiscent of Arctic ice:cool"
  "rose-gold:#e11d48:Elegant pink golds:elegant"
  "obsidian:#1f2937:Pure dark high contrast theme:dark"
  "ivory:#f5f5f4:Clean light mode theme:light"
  "amber-alert:#f59e0b:High visibility accessibility theme:accessible"
  "cyberpunk-neon:#a855f7:Bright neon purples and pinks:vibrant"
  "monochrome-elite:#6b7280:Professional grayscale theme:professional"
  "ocean-depth:#0369a1:Deep sea blues:cool"
  "desert-mirage:#d97706:Warm sandy tones:warm"
  "lavender-dreams:#9333ea:Soft dreamy purples:elegant"
  "emerald-matrix:#059669:Matrix-inspired greens:vibrant"
  "cherry-blossom:#ec4899:Soft pink blossoms:elegant"
)

for theme in "${themes[@]}"; do
  IFS=':' read -r name color desc category <<< "$theme"
  
  cat > "${name}.json" << EOF
{
  "name": "${name//-/ }",
  "description": "${desc}",
  "sourceColor": "${color}",
  "category": "${category}",
  "author": "MD3 Theme Builder",
  "version": "1.0",
  "createdAt": "$(date -Iseconds)"
}
EOF
done

echo "Created ${#themes[@]} theme presets"
