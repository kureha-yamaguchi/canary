#!/bin/bash
# Sync all branches from kureha-yamaguchi/canary to shayahal/canary

echo "Fetching all branches from origin..."
git fetch origin

echo "Pushing all branches to shayahal..."
git push shayahal --all

echo "Pushing all tags to shayahal..."
git push shayahal --tags

echo "✅ All branches and tags synced!"

