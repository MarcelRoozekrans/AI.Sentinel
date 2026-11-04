namespace AI.Sentinel.Approvals.Semantic;

/// <summary>The destructive examples a semantic approval scores against when none are configured.</summary>
internal static class SemanticApprovalExamples
{
    /// <summary>Placeholder similarity threshold; calibrated later.</summary>
    public const float DefaultThreshold = 0.80f;

    /// <summary>Phrased the way they appear in commands, HTTP calls and SQL.</summary>
    public static readonly string[] Default =
    [
        // Namespace and cluster deletion
        "kubectl delete namespace production",
        "kubectl delete ns prod --all --force",
        "kubectl delete all --all --all-namespaces",
        "kubectl delete cluster prod-cluster",
        "helm uninstall production-release --namespace production",
        // Databases
        "DROP DATABASE customers;",
        "DROP TABLE users;",
        "TRUNCATE TABLE orders;",
        "DELETE FROM accounts;",
        "DROP SCHEMA public CASCADE;",
        // Files
        "rm -rf /",
        "rm -rf ~/*",
        "rm -rf /var/lib/postgresql/data",
        "Remove-Item -Recurse -Force C:\\",
        "find / -name '*' -delete",
        // Version control
        "git push --force origin main",
        "git push origin --delete main",
        "git reset --hard HEAD~100 && git clean -fdx",
        // Mass purge and delete
        "DELETE https://api.example.com/v1/users?all=true",
        "aws s3 rm s3://production-bucket --recursive",
        "aws s3 rb s3://production-bucket --force",
        "gsutil rm -r gs://production-bucket",
        "redis-cli FLUSHALL",
        "DELETE /_all",
        // Cloud resource deletion
        "az group delete --name production-rg --yes --no-wait",
        "gcloud projects delete production-project",
        "aws ec2 terminate-instances --instance-ids i-0abcd1234efgh5678",
        "terraform destroy -auto-approve",
        // Key and credential revocation
        "aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE",
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
