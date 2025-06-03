import { 
  S3Client, 
  PutObjectCommand, 
  GetObjectCommand, 
  DeleteObjectCommand,
  CreateBucketCommand,
  HeadBucketCommand
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import * as storage from "./storage";
import { BlobStorageProvider } from "./blob-storage-provider";
import * as http from 'http';
import * as url from 'url';

export class S3BlobProvider implements BlobStorageProvider {
  private _enableSecureUrl: boolean;
  private _signUrlExpiration: number;

  constructor(private _s3Client: S3Client, private _bucketName: string) {
    // Parse environment variables with defaults
    this._enableSecureUrl = process.env.S3_SECURE_URL_ENABLE?.toLowerCase() === 'true';
    this._signUrlExpiration = Number(process.env.S3_SIGN_URL_EXPIRATION || '3600');
  }

  private getS3Key(container: string, key: string): string {
    return `${container}/${key}`;
  }

  private handleError(error: any, operation: string): Error {
    console.error(`S3 ${operation} error:`, error);
    return storage.storageError(
      storage.ErrorCode.Other, 
      `S3 ${operation} failed: ${error.message || 'Unknown error'}`
    );
  }

  async uploadBlob(container: string, blobId: string, content: Buffer | string, contentLength?: number): Promise<void> {
    try {
      console.log(`S3BlobProvider: Uploading blob to ${container}/${blobId}, size: ${contentLength || (typeof content === 'string' ? content.length : content.byteLength)} bytes`);
      
      // Convert content to Buffer if it's a string
      const body = Buffer.isBuffer(content) ? content : Buffer.from(content);
      
      // Use a simplified command object with minimal properties
      const command = new PutObjectCommand({
        Bucket: this._bucketName,
        Key: this.getS3Key(container, blobId),
        Body: body,
        // If secure URLs are not enabled, make objects public
        ...(this._enableSecureUrl ? {} : { ACL: 'public-read' }),
        // ContentLength causes issues with MinIO and SHA256 calculation
        // Do not include ContentLength, ContentType, or Content-MD5
      });
      
      // Try upload with our own retry mechanism
      let attempts = 0;
      const maxAttempts = 3;
      let lastError = null;
      
      while (attempts < maxAttempts) {
        try {
          console.log(`S3BlobProvider: Upload attempt ${attempts + 1}/${maxAttempts} for ${container}/${blobId}`);
          await this._s3Client.send(command);
          console.log(`S3BlobProvider: Successfully uploaded blob to ${container}/${blobId}`);
          return; // Success!
        } catch (error: any) {
          lastError = error;
          attempts++;
          
          // Check if this is a SHA256 mismatch error
          if (error.Code === 'XAmzContentSHA256Mismatch') {
            console.error(`S3BlobProvider: SHA256 mismatch error on attempt ${attempts}/${maxAttempts}`);
            
            // Try alternative strategy for small files
            if (body.length < 10240 && attempts === 1) { // Less than 10KB on first retry
              try {
                console.log("Trying alternative upload approach for small file...");
                // For small files, try with a string body instead of buffer
                const altCommand = new PutObjectCommand({
                  Bucket: this._bucketName,
                  Key: this.getS3Key(container, blobId),
                  Body: body.toString('utf8') // Convert buffer to string
                });
                
                await this._s3Client.send(altCommand);
                console.log(`S3BlobProvider: Alternative upload successful for ${container}/${blobId}`);
                return; // Success with alternative method
              } catch (altError) {
                console.error("Alternative upload failed:", altError);
                // Continue with regular retries
              }
            }
          }
          
          if (attempts < maxAttempts) {
            // Wait before retry (exponential backoff)
            const backoffTime = Math.pow(2, attempts) * 500; // Longer backoff times
            console.log(`Retrying in ${backoffTime}ms...`);
            await new Promise(resolve => setTimeout(resolve, backoffTime));
          }
        }
      }
      
      // If we get here, all attempts failed
      throw lastError;
    } catch (error) {
      console.error(`S3BlobProvider: Error uploading blob to ${container}/${blobId}:`, error);
      throw this.handleError(error, "upload");
    }
  }

  async downloadBlob(container: string, blobId: string): Promise<Buffer> {
    try {
      console.log(`S3BlobProvider: Downloading blob from ${container}/${blobId}`);
      const command = new GetObjectCommand({
        Bucket: this._bucketName,
        Key: this.getS3Key(container, blobId)
      });
      
      const response = await this._s3Client.send(command);
      if (!response.Body) {
        throw new Error("Empty response body");
      }
      
      // Convert the readable stream to a buffer
      const chunks: Uint8Array[] = [];
      const stream = response.Body as any;
      
      for await (const chunk of stream) {
        chunks.push(chunk);
      }
      
      return Buffer.concat(chunks);
    } catch (error: any) {
      // If the blob doesn't exist and it's a history blob, return an empty array
      if (error.name === "NoSuchKey" && container === "packagehistoryv1") {
        console.log(`S3BlobProvider: History blob ${blobId} not found, returning empty array`);
        return Buffer.from("[]");
      }
      console.error(`S3BlobProvider: Error downloading blob from ${container}/${blobId}:`, error);
      throw this.handleError(error, "download");
    }
  }

  async deleteBlob(container: string, blobId: string): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: this._bucketName,
      Key: this.getS3Key(container, blobId)
    });
    
    await this._s3Client.send(command);
  }

  async getBlobUrl(container: string, blobId: string): Promise<string> {
    const objectKey = this.getS3Key(container, blobId);

    if (this._enableSecureUrl) {
      // Generate signed URL with configurable expiration
      const command = new GetObjectCommand({
        Bucket: this._bucketName,
        Key: objectKey
      });
      return getSignedUrl(this._s3Client, command, { expiresIn: this._signUrlExpiration });
    } else {
      const endpoint = process.env.S3_ENDPOINT || 'http://localhost:9000';
      const objectAccessKey = process.env.S3_OBJECT_ACCESS_KEY;
      const customDomainEndpoint = process.env.S3_CUSTOM_DOMAIN || '';
      // Return public URL
      if(customDomainEndpoint && customDomainEndpoint.length > 5) {
        return `${customDomainEndpoint}/${objectKey}`;
      }else{
        return `${endpoint}/${objectAccessKey}:${this._bucketName}/${objectKey}`;
      }        
    }
  }

  async ensureBucketExists(): Promise<void> {
    try {
      console.log(`Ensuring S3 bucket '${this._bucketName}' exists...`);
      
      // Check if bucket exists by trying to access its properties
      const headBucketCommand = new HeadBucketCommand({ Bucket: this._bucketName });
      
      try {
        await this._s3Client.send(headBucketCommand);
        console.log(`S3 bucket '${this._bucketName}' already exists`);
      } catch (error: any) {
        if (error.name === 'NotFound' || error.name === 'NoSuchBucket') {
          console.log(`Creating S3 bucket '${this._bucketName}'...`);
          const createBucketCommand = new CreateBucketCommand({
            Bucket: this._bucketName
          });
          await this._s3Client.send(createBucketCommand);
          console.log(`Created S3 bucket '${this._bucketName}'`);
        } else {
          throw error;
        }
      }
    } catch (error) {
      console.error(`Error ensuring bucket exists:`, error);
      throw error;
    }
  }

  async createContainer(container: string, options?: any): Promise<void> {
    // First ensure the bucket exists
    await this.ensureBucketExists();
    
    // S3 doesn't require explicit container creation since folders
    // are created implicitly when objects are uploaded with path prefixes
    console.log(`S3 container '${container}' ready (no explicit creation needed)`);
  }

  async checkHealth(container: string): Promise<void> {
    try {
      console.log(`S3BlobProvider: Checking health of ${container}`);
      const command = new GetObjectCommand({
        Bucket: this._bucketName,
        Key: this.getS3Key(container, "health")
      });
      
      try {
        const response = await this._s3Client.send(command);
        const bodyContents = await response.Body?.transformToString();
        
        if (bodyContents !== "health") {
          throw storage.storageError(
            storage.ErrorCode.ConnectionFailed,
            "The S3 service failed the health check for " + container
          );
        }
        console.log(`S3BlobProvider: Health check passed for ${container}`);
      } catch (error: any) {
        // If health check file doesn't exist, try to create it
        if (error.name === "NoSuchKey") {
          console.log(`S3BlobProvider: Health check file not found in ${container}, creating it`);
          try {
            await this.uploadBlob(container, "health", "health", "health".length);
            console.log(`S3BlobProvider: Created health check file in ${container}`);
            return; // Successfully created health check file
          } catch (uploadError: any) {
            console.error(`S3BlobProvider: Failed to create health check file in ${container}:`, uploadError);
            throw storage.storageError(
              storage.ErrorCode.ConnectionFailed,
              `Failed to create health check file in S3: ${uploadError.message}`
            );
          }
        } else {
          throw this.handleError(error, "health check");
        }
      }
    } catch (error: any) {
      console.error(`S3BlobProvider: Health check failed for ${container}:`, error);
      throw this.handleError(error, "health check");
    }
  }

  private async uploadViaHttp(bucket: string, key: string, body: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      const endpoint = url.parse(process.env.S3_ENDPOINT || 'http://localhost:9000');
      
      const options = {
        hostname: endpoint.hostname,
        port: endpoint.port,
        path: `/${bucket}/${key}`,
        method: 'PUT',
        headers: {
          'Content-Length': body.length,
          'Content-Type': 'application/octet-stream',
          'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD',
          'Authorization': `AWS4-HMAC-SHA256 Credential=${process.env.S3_ACCESS_KEY}/${new Date().toISOString().slice(0, 10)}/${process.env.S3_REGION || 'us-east-1'}/s3/aws4_request`
        }
      };
      
      const req = http.request(options, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Failed to upload: ${res.statusCode}`));
          return;
        }
        
        resolve();
      });
      
      req.on('error', (error) => {
        reject(error);
      });
      
      req.write(body);
      req.end();
    });
  }
} 