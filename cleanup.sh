#!/usr/bin/env bash
set -euo pipefail

ids=$(gh api '/orgs/wow-look-at-my/packages/container/secret-server/versions' --paginate --jq '.[] | select(.metadata.container.tags | any(startswith("sha-"))) | .id')
total=$(echo "$ids" | wc -l | tr -d ' ')
i=0

for id in $ids; do
	i=$((i + 1))
	gh api --method DELETE "/orgs/wow-look-at-my/packages/container/secret-server/versions/$id" 2>&1
	echo "[$i/$total] deleted $id"
done

echo "done"
