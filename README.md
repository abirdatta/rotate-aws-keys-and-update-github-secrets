# rotate-aws-keys-and-update-github-secrets
Python program to rotate aws keys and update github secrets. 


If you are using aws user security crendentials to perform operations in aws, via terraform or other programmatic ways, its a good securtiy practice to rotate the aws keys at an interval may be every hour or may be once a month.
This is created keeping in mind workflow execution in Github action.

Scenario - 

All terraform execution or any aws change happens via github actions and credentials are stored in github secrets.

The workflow job uses environment variables to pass in aws user details for which to rotate keys and github secret names to be updated.
Sample workflow file
```
name: scheduler-rotate-aws-user-keys
on:
 push:
   tags:
     - ROTATE-KEYS-ALL-*
 schedule:
   # The cron will run first day of the month
   - cron:  '0 0 1 * *'
jobs:
  rotate-keys:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repo
        uses: actions/checkout@master

      - name: Rotate aws user keys
        working-directory: rotate_aws_keys
        run: |
          pip install -r requirements.txt
          python rotate_aws_keys.py
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY }}
          AWS_SECRET_ACCESS_KEY:  ${{ secrets.AWS_SECRET_KEY }}
          AWS_DEFAULT_REGION: ${{ secrets.AWS_DEFAULT_REGION }}
          AWS_TERRA_USER: terra_user
          GITHUB_ACCESS_TOKEN: ${{ secrets.GITHUB_ACCESS_TOKEN}}
          GITHUB_REPO: abirdatta/testing
          GITHUB_SECRET_SECRET_ACCESS_KEY: AWS_ACCESS_KEY
          GITHUB_SECRET_ACCESS_KEY_ID: AWS_SECRET_KEY
