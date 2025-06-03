// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as express from "express";
import * as defaultServer from "./default-server";

const https = require("https");
const fs = require("fs");

async function testS3Connection() {
  if (process.env.STORAGE_TYPE === 'S3') {
    try {
      console.log('Testing S3 connection...');
      const S3Client = require('@aws-sdk/client-s3').S3Client;
      const ListBucketsCommand = require('@aws-sdk/client-s3').ListBucketsCommand;
      
      const s3 = new S3Client({
        region: process.env.S3_REGION || "us-east-1",
        endpoint: process.env.S3_ENDPOINT,
        credentials: {
          accessKeyId: process.env.S3_ACCESS_KEY || "",
          secretAccessKey: process.env.S3_SECRET_KEY || "",
        },
        forcePathStyle: true
      });
      
      const data = await s3.send(new ListBucketsCommand({}));
      console.log('✅ S3 connection successful');
      console.log('Available buckets:', data.Buckets?.map(b => b.Name).join(', '));
    } catch (error) {
      console.error('❌ S3 connection test failed:', error);
    }
  }
}

testS3Connection();

defaultServer.start(function (err: Error, app: express.Express) {
  if (err) {
    throw err;
  }

  const httpsEnabled: boolean = Boolean(process.env.HTTPS) || false;
  const defaultPort: number = httpsEnabled ? 8443 : 3000;

  const port: number = Number(process.env.API_PORT) || Number(process.env.PORT) || defaultPort;
  let server: any;

  if (httpsEnabled) {
    const options = {
      key: fs.readFileSync("./certs/cert.key", "utf8"),
      cert: fs.readFileSync("./certs/cert.crt", "utf8"),
    };

    server = https.createServer(options, app).listen(port, function () {
      console.log("API host listening at https://localhost:" + port);
    });
  } else {
    server = app.listen(port, function () {
      console.log("API host listening at http://localhost:" + port);
    });
  }

  server.setTimeout(0);
});
