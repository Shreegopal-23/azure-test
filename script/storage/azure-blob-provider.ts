import { BlobServiceClient } from "@azure/storage-blob";
import * as storage from "./storage";
import { BlobStorageProvider } from "./blob-storage-provider";

export class AzureBlobProvider implements BlobStorageProvider {
  constructor(private _blobService: BlobServiceClient) {}

  async uploadBlob(container: string, blobId: string, content: Buffer | string, contentLength?: number): Promise<void> {
    const length = contentLength || (typeof content === 'string' ? content.length : content.byteLength);
    await this._blobService.getContainerClient(container).uploadBlockBlob(blobId, content, length);
  }

  async downloadBlob(container: string, blobId: string): Promise<Buffer> {
    return await this._blobService.getContainerClient(container).getBlobClient(blobId).downloadToBuffer();
  }

  async deleteBlob(container: string, blobId: string): Promise<void> {
    await this._blobService.getContainerClient(container).deleteBlob(blobId);
  }

  async getBlobUrl(container: string, blobId: string): Promise<string> {
    return this._blobService.getContainerClient(container).getBlobClient(blobId).url;
  }

  async createContainer(container: string, options?: any): Promise<void> {
    await this._blobService.createContainer(container, options);
  }

  async checkHealth(container: string): Promise<void> {
    try {
      const blobContents = await this._blobService
        .getContainerClient(container)
        .getBlobClient("health")
        .downloadToBuffer();
      
      if (blobContents.toString() !== "health") {
        throw storage.storageError(
          storage.ErrorCode.ConnectionFailed,
          "The Azure Blobs service failed the health check for " + container
        );
      }
    } catch (error) {
      throw error;
    }
  }
} 