namespace AI.Sentinel.Approvals.Semantic;

/// <summary>The destructive examples a semantic approval scores against when none are configured.</summary>
internal static class SemanticApprovalExamples
{
    /// <summary>The similarity at or above which a call asks for approval. Tuned with ComplianceEval
    /// <c>--approvals</c> on all-MiniLM-L6-v2: the lowest value at 0.01 steps above every held-out benign score.</summary>
    public const float DefaultThreshold = 0.80f;

    /// <summary>Phrased the way they appear in commands, HTTP calls and SQL.</summary>
    public static readonly string[] Default =
    [
        // Namespace and cluster deletion
        "kubectl delete namespace production",
        "kubectl delete ns prod --all --force",
        "kubectl delete all --all -n production",
        "kubectl delete persistentvolumeclaims --all --namespace production",
        "oc delete project production",
        "kubectl delete cluster prod-cluster",
        "helm uninstall production-release --namespace production",
        // Databases
        "DROP DATABASE customers;",
        "DROP TABLE users;",
        "TRUNCATE TABLE orders;",
        "DELETE FROM accounts;",
        "DROP SCHEMA public CASCADE;",
        "psql -c \"DROP DATABASE analytics;\"",
        "mysql -e 'DROP TABLE customers'",
        "mongosh --eval 'db.dropDatabase()'",
        "DELETE FROM sessions WHERE true;",
        "mysql -u root -e 'DROP DATABASE production'",
        "psql -U postgres -c \"DROP TABLE orders CASCADE;\"",
        "DELETE FROM users WHERE 1=1;",
        // Files
        "rm -rf /",
        "rm -rf ~/*",
        "rm -rf /home/app/data",
        "sudo rm -rf /opt/app",
        "rm -fr /srv/data",
        "rm -rf /var/lib/postgresql/data",
        "Remove-Item -Recurse -Force C:\\",
        "find / -name '*' -delete",
        // Version control
        "git push --force origin main",
        "git push origin --delete main",
        "git push -f origin master",
        "gh repo delete acme/api --yes",
        "git reset --hard HEAD~100 && git clean -fdx",
        // Mass purge and delete
        "DELETE https://api.example.com/v1/users?all=true",
        "aws s3 rm s3://production-bucket --recursive",
        "aws s3 rb s3://production-bucket --force",
        "gsutil rm -r gs://production-bucket",
        "redis-cli FLUSHALL",
        "DELETE /_all",
        "curl -X DELETE https://api.example.com/v1/projects/7",
        "docker system prune --all --volumes --force",
        // Cloud resource deletion
        "az group delete --name production-rg --yes --no-wait",
        "gcloud projects delete production-project",
        "aws ec2 terminate-instances --instance-ids i-0abcd1234efgh5678",
        "terraform destroy -auto-approve",
        "pulumi destroy --yes",
        "aws rds delete-db-cluster --db-cluster-identifier production --skip-final-snapshot",
        "aws cloudformation delete-stack --stack-name production",
        "gcloud sql instances delete production-db",
        "az keyvault delete --name production-vault",
        // Key and credential revocation
        "aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE",
        "aws iam delete-user --user-name admin",
        "aws kms schedule-key-deletion --key-id 1234abcd-12ab-34cd-56ef-1234567890ab",
        "gcloud iam service-accounts keys delete key-id --iam-account sa@project.iam.gserviceaccount.com",
        "vault token revoke -mode=orphan -self",
        "gpg --delete-secret-keys admin@example.com",
        "az ad app credential delete --id 00000000-0000-0000-0000-000000000000 --key-id 11111111-1111-1111-1111-111111111111",
        // Disk format and wipe
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "shred -vfz -n 3 /dev/sda",
        "wipefs --all /dev/nvme0n1",
        "Format-Volume -DriveLetter C -Force",
    ];
}
