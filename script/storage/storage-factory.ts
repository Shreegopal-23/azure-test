import { BlobServiceClient, StorageSharedKeyCredential } from "@azure/storage-blob";
import { S3Client, S3ClientConfig } from "@aws-sdk/client-s3";
import { NodeHttpHandler } from "@aws-sdk/node-http-handler";
import * as https from "https";
import { AzureBlobProvider } from "./azure-blob-provider";
import { S3BlobProvider } from "./s3-blob-provider";
import { BlobStorageProvider } from "./blob-storage-provider";

// For local S3 instances to disable SSL cert validation
class HttpsAgent extends https.Agent {
  constructor(options) {
    super(options);
  }
}

export class StorageFactory {
  public static createBlobStorageProvider(): BlobStorageProvider {
    const storageType = process.env.STORAGE_TYPE || "AZURE";
    
    if (storageType === "S3") {
      console.log("✅ Using S3 for blob storage");
      
      // Get S3 configuration from environment
      const region = process.env.S3_REGION || "us-east-1";
      const endpoint = process.env.S3_ENDPOINT;
      const accessKey = process.env.S3_ACCESS_KEY || "";
      const secretKey = process.env.S3_SECRET_KEY || "";
      const bucketName = process.env.S3_BUCKET_NAME || "codepush-bucket";
      
      console.log(`S3 Configuration:
- Endpoint: ${endpoint}
- Bucket: ${bucketName}
- Region: ${region}
- Access Key: ${accessKey ? "Set" : "Not Set"}
- Secret Key: ${secretKey ? "Set" : "Not Set"}`);
      
      // Check if we're using MinIO or similar local S3 service
      const isLocalS3 = endpoint && (
        endpoint.includes("localhost") || 
        endpoint.includes("127.0.0.1") ||
        endpoint.includes("minio") ||
        process.env.S3_MINIO_COMPATIBILITY === "true"
      );
      
      // Use a more compatible configuration for MinIO
      const s3Config: S3ClientConfig = {
        region: region,
        endpoint: endpoint,
        credentials: {
          accessKeyId: accessKey,
          secretAccessKey: secretKey,
        },
        forcePathStyle: true,
        // Add MinIO-specific settings
        maxAttempts: 1 // Don't retry internally (we handle retries ourselves)
      };
      
      // Add specialized options for MinIO
      if (isLocalS3) {
        // Disable TLS verification for local development
        (s3Config as any).tls = false;
        
        // For MinIO, we need to specifically set these flags:
        (s3Config as any).signingEscapePath = true;
        (s3Config as any).useArnRegion = true;
        (s3Config as any).retryMode = "standard";
        
        // Apply special handlers for local development
        try {
          const requestHandler = new NodeHttpHandler({
            httpsAgent: new HttpsAgent({
              rejectUnauthorized: false
            })
          });
          s3Config.requestHandler = requestHandler;
        } catch (error) {
          console.warn("Could not create custom request handler:", error);
        }
        
        console.log("Using MinIO-compatible configuration");
      }
      
      // Create client with properly typed config
      const s3Client = new S3Client(s3Config);
      
      // Create and return S3 blob provider
      return new S3BlobProvider(s3Client, bucketName);
    } else {
      console.log("✅ Using Azure for blob storage");
      
      // Default to Azure
      let blobService;
      
      if (process.env.EMULATED === 'true') {
        console.log("Using emulated Azure storage");
        blobService = BlobServiceClient.fromConnectionString("UseDevelopmentStorage=true");
      } else {
        const accountName = process.env.AZURE_STORAGE_ACCOUNT;
        const accountKey = process.env.AZURE_STORAGE_ACCESS_KEY;
        
        if (!accountName || !accountKey) {
          throw new Error("Azure storage credentials not set");
        }
        
        console.log(`Azure Storage Account: ${accountName}`);
        
        const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);
        blobService = new BlobServiceClient(
          `https://${accountName}.blob.core.windows.net`,
          sharedKeyCredential
        );
      }
      
      return new AzureBlobProvider(blobService);
    }
  }
} 