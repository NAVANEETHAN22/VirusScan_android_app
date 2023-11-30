package com.example.virusscan;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class LinkScannerActivity extends AppCompatActivity {

    private EditText urlEditText;
    private Button scanLinkButton;
    private WebView webView;

    @SuppressLint("MissingInflatedId")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_link_scanner); // Set the correct layout resource

        urlEditText = findViewById(R.id.urlEditText);
        scanLinkButton = findViewById(R.id.scanLinkButton);
        webView = findViewById(R.id.webView);

        scanLinkButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String url = urlEditText.getText().toString();
                if (!url.isEmpty()) {
                    System.out.println(url);
                    scanUrl(url);
                } else {
                    // Use getApplicationContext() to get the application context
                    Toast.makeText(getApplicationContext(), "Please enter a URL", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private void scanUrl(String url) {
        // VirusTotal API Key (Replace with your own key)
        String apiKey = "295de35edadea66bc3bf901dc5024a0006ac01e7cd8e949496f22fae1444da21";

        // VirusTotal API Endpoint
        String apiUrl = "https://www.virustotal.com/vtapi/v2/url/report";

        // Build the URL for the VirusTotal API request
        String requestUrl = apiUrl + "?apikey=" + apiKey + "&resource=" + url;

        // Create an OkHttpClient to make the API request
        OkHttpClient client = new OkHttpClient();

        // Create a request to fetch the scan result
        Request request = new Request.Builder()
                .url(requestUrl)
                .build();

        // Make the asynchronous API request
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(LinkScannerActivity.this, "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                });
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    final String responseBody = response.body().string();

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                JSONObject resultJson = new JSONObject(responseBody);
                                int positives = resultJson.getInt("positives");

                                // Display the scan result
                                String scanResult;
                                if (positives > 0) {
                                    scanResult = "This site is malicious";
                                } else {
                                    scanResult = "This site is not malicious";
                                }

                                // Append the scan result to the WebView content
                                String htmlContent = resultJson.toString(4) + "<br/><br/>" + scanResult;
                                webView.loadData(htmlContent, "text/html", null);
                            } catch (JSONException e) {
                                e.printStackTrace();
                                Toast.makeText(LinkScannerActivity.this, "Error parsing JSON response", Toast.LENGTH_SHORT).show();
                            }
                        }
                    });
                } else {
                    // Handle the response error here
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(LinkScannerActivity.this, "Error: " + response.message(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            }
        });
    }
}
