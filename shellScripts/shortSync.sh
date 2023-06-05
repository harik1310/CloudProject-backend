# #syncing aws resources to postgres
echo 'syncing aws'
cloudquery sync shellScripts/yamlfiles/short_aws_source.yaml  shellScripts/yamlfiles/postgresql.yaml

# #syncing gcp resources to postgres 
echo 'syncing gcp'
cloudquery sync shellScripts/yamlfiles/short_gcp.yaml  shellScripts/yamlfiles/postgresql.yaml       		

# #syncing azure resources to postgres
echo 'syncing azure'
cloudquery sync  shellScripts/yamlfiles/short_azure.yaml  shellScripts/yamlfiles/postgresql.yaml


