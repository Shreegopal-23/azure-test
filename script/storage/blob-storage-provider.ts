import * as q from "q";

/**
 * Interface for blob storage operations
 */
export interface BlobStorageProvider {
  /**
   * Uploads a blob to the specified container
   */
  uploadBlob(container: string, blobId: string, content: Buffer | string, contentLength?: number): Promise<void>;
  
  /**
   * Downloads a blob from the specified container
   */
  downloadBlob(container: string, blobId: string): Promise<Buffer>;
  
  /**
   * Deletes a blob from the specified container
   */
  deleteBlob(container: string, blobId: string): Promise<void>;
  
  /**
   * Gets a URL for a blob in the specified container
   */
  getBlobUrl(container: string, blobId: string): Promise<string>;
  
  /**
   * Creates a container with the specified options
   */
  createContainer(container: string, options?: any): Promise<void>;
  
  /**
   * Checks the health of the storage provider
   */
  checkHealth(container: string): Promise<void>;
} 