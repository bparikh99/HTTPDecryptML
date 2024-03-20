using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Azure.Storage.Blobs;
using PgpCore;
using System.Text;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Azure.Storage.Blobs.Models;
using System.Net.Http;
using System.Net;

namespace Company.Function
{
    class errorInfo
    {
        public string code { get; set; }
        public string description { get; set; }
        public string message { get; set; }
        public string reason { get; set; }
    }
    public static class HTTPDecryptBlob
    {
        [FunctionName("HTTPDecryptBlob")]
        public static async Task<HttpResponseMessage> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = null;
            try
            {
                data = JsonConvert.DeserializeObject(requestBody);
            }
            catch (Exception ex)
            {
                errorInfo appErrorInfo = new errorInfo();
                appErrorInfo.code = ex.HResult.ToString();
                appErrorInfo.description = ex.Message;
                appErrorInfo.message = ex.Message;
                appErrorInfo.reason = "Internal Server Error";
                return new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(appErrorInfo, Formatting.Indented), Encoding.UTF8, "application/json")
                };

            }
            errorInfo dataErrorInfo = new errorInfo();
            dataErrorInfo.code = "400";
            dataErrorInfo.description = "Data Validation Failed";
            dataErrorInfo.reason = "Bad Request";

            string missingParameters = "";
            string emptyParameters = "";
            string[] reqdParameters = { "privateKey", "privateKeyPassPhrase", "SourceBlobName", "sourceContainerName", "storageAccountName", "keyVaultName", "destContainerName"};
            for(int i = 0; i < reqdParameters.Length; i++)
            {
                if (!data.ContainsKey(reqdParameters[i]))
                {
                    missingParameters += reqdParameters[i] + "; ";
                }
                else if (String.IsNullOrEmpty((string)data.GetValue(reqdParameters[i])))
                {
                    emptyParameters += reqdParameters[i] + "; ";

                }
            }
            
            if (missingParameters.Length > 0 && missingParameters != "")
            {

                dataErrorInfo.message = "The following parameters are required: " + missingParameters;
                return new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(dataErrorInfo, Formatting.Indented), Encoding.UTF8, "application/json")
                };
            }
            if (emptyParameters.Length > 0 && emptyParameters != "")
            {
                dataErrorInfo.message = "The following parameters are required, cannot be empty: " + emptyParameters;
                return new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(dataErrorInfo, Formatting.Indented), Encoding.UTF8, "application/json")
                };
            }
            //Deserilaizing the req body and checking if the field exists or not

            string privateKey = data?.privateKey;
            string privateKeyPassPhrase = data?.privateKeyPassPhrase;
            string SourceBlobName = data?.SourceBlobName;
            string containerName = data?.sourceContainerName;
            string destcontainerName = data?.destContainerName;
            string storageAccountName = data?.storageAccountName;
            string keyVaultName = data?.keyVaultName;



            //defining kv uri and storage account string to be used
            try {
                var kvUri = "https://" + keyVaultName + ".vault.azure.net";
                var client = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
                var blobServiceClient = new BlobServiceClient(new Uri($"https://{storageAccountName}.blob.core.windows.net"), new DefaultAzureCredential());



                var privateKeysecretValue = await client.GetSecretAsync(privateKey);
                string keyContent = privateKeysecretValue.Value.Value;

                var passphraseSecretValue = await client.GetSecretAsync(privateKeyPassPhrase);
                string pphrase = passphraseSecretValue.Value.Value;

                BlobContainerClient containerClient = blobServiceClient.GetBlobContainerClient(containerName);
                BlobContainerClient outcontainerClient = blobServiceClient.GetBlobContainerClient(destcontainerName);

                BlobClient blobClient = containerClient.GetBlobClient(SourceBlobName);
                BlobClient outblobClient = outcontainerClient.GetBlobClient(SourceBlobName);
                var inputString = "";
                if (await blobClient.ExistsAsync())
                {
                    var response = await blobClient.DownloadAsync();
                    using (var streamReader = new StreamReader(response.Value.Content))
                    {
                        inputString = streamReader.ReadToEnd();
                    }
                }
                else
                {

                    dataErrorInfo.message = "File not found";
                    return new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        Content = new StringContent(JsonConvert.SerializeObject(dataErrorInfo, Formatting.Indented), Encoding.UTF8, "application/json")
                    };
                }

                Stream inputStream = GenerateStreamFromString(inputString);

                if (inputStream == null || inputStream.Length <= 0)
                {
                    dataErrorInfo.message = "The input stream is empty, make sure the file contains data";

                    return new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        Content = new StringContent(JsonConvert.SerializeObject(dataErrorInfo, Formatting.Indented), Encoding.UTF8, "application/json")
                    };
                }

                byte[] privateKeyBytes = Convert.FromBase64String(keyContent);
                string privateKeyEncoded = Encoding.UTF8.GetString(privateKeyBytes);

                Stream decryptedData = await DecryptAsync(inputStream, privateKeyEncoded, pphrase, log);
                outblobClient.Upload(decryptedData, overwrite: true);
                
                }
            catch (Exception ex)
            {
                errorInfo appErrorInfo = new errorInfo();
                appErrorInfo.code = ex.HResult.ToString();
                appErrorInfo.description = ex.Message;
                appErrorInfo.message = ex.Message;
                appErrorInfo.reason = "Internal Server Error";
                return new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(appErrorInfo, Formatting.Indented), Encoding.UTF8, "application/json")
                };

            }
            

            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
        private static async Task<Stream> DecryptAsync(Stream inputStream, string privateKey, string pphrase,ILogger log)
        {
            try
            {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();
                log.LogInformation("inside decrypt func");
                using (inputStream)
                using (Stream privateKeyStream = GenerateStreamFromString(privateKey))
                {
                    
                    await pgp.DecryptStreamAsync(inputStream, outputStream, privateKeyStream, pphrase);
                    
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Error during decryption: {ErrorMessage}", ex.Message);
                throw; // Rethrow the exception to propagate it to the caller
            }
        }
        private static Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }
}
