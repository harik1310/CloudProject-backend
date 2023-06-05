# #syncing aws resources to postgres
echo 'syncing aws'
cloudquery sync shellScripts/yamlfiles/aws_source.yaml  shellScripts/yamlfiles/postgresql.yaml

# #syncing gcp resources to postgres 
echo 'syncing gcp'
cloudquery sync shellScripts/yamlfiles/gcp.yaml  shellScripts/yamlfiles/postgresql.yaml       		

# #syncing azure resources to postgres
echo 'syncing azure'
cloudquery sync  shellScripts/yamlfiles/azure.yaml  shellScripts/yamlfiles/postgresql.yaml


