package com.example.virusscan;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {

    private static final int FILE_PICK_REQUEST = 1;

    private Button uploadButton;
    private ProgressBar progressBar;
    private TextView resultTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        uploadButton = findViewById(R.id.uploadButton);

        progressBar = findViewById(R.id.progressBar);
        resultTextView = findViewById(R.id.resultTextView);

        uploadButton.setOnClickListener(view -> pickFileForUpload());
    }

    private void pickFileForUpload() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        startActivityForResult(intent, FILE_PICK_REQUEST);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_PICK_REQUEST && resultCode == RESULT_OK && data != null) {
            Uri fileUri = data.getData();
            try {
                performVirusTotalScan(fileUri);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void performVirusTotalScan(Uri fileUri) throws FileNotFoundException {
        progressBar.setVisibility(View.VISIBLE);

        displayScanResults("Step 1: Obtaining file input stream");

        // Obtain the InputStream from the fileUri
        InputStream inputStream;
        try {
            inputStream = getContentResolver().openInputStream(fileUri);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            displayScanResults("Error: File not found.");
            return;
        }

        displayScanResults("Step 2: Creating custom RequestBody");

        // Create a custom RequestBody using the InputStream
        InputStreamRequestBody requestBody = new InputStreamRequestBody(
                MediaType.parse("application/octet-stream"),
                getContentResolver().openInputStream(fileUri)
        );

        String fileHash = calculateSHA256Hash(fileUri);
        String requestUrl = "https://www.virustotal.com/api/v3/files/" + fileHash;
        // Build the request using the GET method
        Request request = new Request.Builder()
                .url(requestUrl)
                .addHeader("x-apikey", "295de35edadea66bc3bf901dc5024a0006ac01e7cd8e949496f22fae1444da21")
                .addHeader("accept", "application/json")
                .build();

        OkHttpClient client = new OkHttpClient();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                runOnUiThread(() -> displayScanResults("Error: " + e.getMessage()));
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String responseBody = response.body().string();

                runOnUiThread(() -> {
                    if (responseBody.isEmpty()) {
                        displayScanResults("Error: Empty response");
                        progressBar.setVisibility(View.GONE); // Hide the progress bar
                        return;
                    }

                        try {
                            JSONObject jsonResponse = new JSONObject(responseBody);

                            try {
                                JSONObject dataObject = jsonResponse.getJSONObject("data");
                                JSONObject attributesObject = dataObject.getJSONObject("attributes");
                                JSONObject lastAnalysisStatsObject = attributesObject.getJSONObject("last_analysis_stats");

                                int malicious = lastAnalysisStatsObject.getInt("malicious");
                                int suspicious = lastAnalysisStatsObject.getInt("suspicious");

                                if (malicious + suspicious > 0) {
                                    displayScanResults("Result: This file is malicious\n");
                                } else {
                                    displayScanResults("Result: This file is not malicious\n");
                                }

                                String scanId = dataObject.getString("id");
                                String fileName = attributesObject.getJSONArray("names").getString(0);
                                int fileSize = attributesObject.getInt("size");
                                long scanDate = attributesObject.getLong("last_analysis_date");
                                String fileTypeProb = attributesObject.getString("trid");
                                String fileType = attributesObject.getString("type_description");
                                String typeExtension = attributesObject.getString("type_extension");
                                String typeTag = attributesObject.getString("type_tag");
                                String formattedScanDate = convertUnixTimestampToDate(scanDate);
                                String formattedFileSize = formatFileSize(fileSize);

                                String formattedResult = "Scan Result:\n" +
                                        "Scan ID: " + scanId + "\n" +
                                        "File Name: " + fileName + "\n" +
                                        "File Size: " + formattedFileSize + "\n" +
                                        "Last Scan Date: " + formattedScanDate + "\n" +
                                        "File Type Probability: " + fileTypeProb + "\n" +
                                        "File Type: " + fileType + "\n" +
                                        "Type Extension: " + typeExtension + "\n" +
                                        "Type Tag: " + typeTag;

                                displayScanResults(formattedResult);

                                String formattedData = dataObject.toString(4); // 4 is the indentation level

                                displayScanResults("\n\n\nScan Result:\n" + formattedData);
                            } catch (JSONException e) {
                                displayScanResults("Error parsing JSON response: " + e.getMessage());
                            }

                        } catch (JSONException e) {
                            throw new RuntimeException(e);
                        }
                    progressBar.setVisibility(View.GONE); // Hide the progress bar
                });
            }
        });

    }
    private String convertUnixTimestampToDate(long timestamp) {
        Date date = new Date(timestamp * 1000L); // Convert to milliseconds
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        return dateFormat.format(date);
    }

    private String formatFileSize(long sizeInBytes) {
        double sizeInKB = sizeInBytes / 1024.0;
        if (sizeInKB < 1024) {
            return String.format("%.2f KB", sizeInKB);
        } else {
            double sizeInMB = sizeInKB / 1024.0;
            return String.format("%.2f MB", sizeInMB);
        }
    }


    private void displayScanResults(String resultText) {
        // Append to existing text and add a newline
        resultTextView.append(resultText + "\n");
    }

    private String calculateSHA256Hash(Uri fileUri) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FileInputStream inputStream = new FileInputStream(getContentResolver().openFileDescriptor(fileUri, "r").getFileDescriptor());

            byte[] buffer = new byte[8192];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }

            byte[] hashBytes = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xFF & hashByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}