          for crate in $(cargo metadata --format-version=1 --no-deps | jq -r '.packages[].manifest_path' | xargs dirname); do
            echo "Publishing crate $crate..."
            cd $crate
            cargo publish --dry-run
            cd ..
          done