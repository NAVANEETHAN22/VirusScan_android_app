package com.example.virusscan;

import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class XSSActivity extends AppCompatActivity {

    private EditText urlEditText;
    private Button scanButton;
    private TextView resultTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_xss);

        urlEditText = findViewById(R.id.urlEditText);
        scanButton = findViewById(R.id.scanButton);
        resultTextView = findViewById(R.id.resultTextView);

        scanButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String url = urlEditText.getText().toString();
                new XSSScannerTask().execute(url);
            }
        });
    }

    private class XSSScannerTask extends AsyncTask<String, Void, String> {

        @Override
        protected String doInBackground(String... params) {
            String url = params[0];
            try {
                Document document = Jsoup.connect(url).get();
                Elements forms = document.select("form");

                List<String> vulnerabilities = new ArrayList<>();

                // Define your payloads here
                String[] payloads = {
                        "<script>alert('XSS')</script>",
                        "<script>alert('XSS');</script>",
                        // Add more payloads here
                };

                for (Element form : forms) {
                    FormDetails formDetails = getFormDetails(form);
                    List<String> formVulnerabilities = new ArrayList<>();

                    for (String payload : payloads) {
                        String content = submitFormAndGetContent(url, formDetails, payload);
                        if (content.contains(payload)) {
                            formVulnerabilities.add(payload);
                        }
                    }

                    if (!formVulnerabilities.isEmpty()) {
                        vulnerabilities.add("Form Action: " + formDetails.action +
                                ", Method: " + formDetails.method +
                                ", Vulnerabilities: " + formVulnerabilities.toString());
                    }
                }

                if (!vulnerabilities.isEmpty()) {
                    return "XSS vulnerabilities found in forms:\n" + String.join("\n", vulnerabilities);
                } else {
                    return "No XSS vulnerabilities detected.";
                }
            } catch (IOException e) {
                e.printStackTrace();
                return "An error occurred: " + e.getMessage();
            } catch (Exception e) {
                e.printStackTrace();
                return "An unexpected error occurred: " + e.getMessage();
            }
        }

        private FormDetails getFormDetails(Element form) {
            FormDetails details = new FormDetails();
            details.action = form.attr("action");
            details.method = form.attr("method");
            List<String> inputNames = new ArrayList<>();

            Elements inputs = form.select("input");
            for (Element input : inputs) {
                inputNames.add(input.attr("name"));
            }
            details.inputNames = inputNames;

            return details;
        }

        private String submitFormAndGetContent(String baseUrl, FormDetails formDetails, String payload) {
            try {
                String targetUrl = baseUrl + formDetails.action;
                Connection connection = Jsoup.connect(targetUrl)
                        .method(Connection.Method.valueOf(formDetails.method))
                        .ignoreHttpErrors(true);

                for (String inputName : formDetails.inputNames) {
                    connection.data(inputName, payload);
                }

                Document response = connection.execute().parse();
                return response.html();
            } catch (IOException e) {
                e.printStackTrace();
                return "";
            }
        }

        private class FormDetails {
            String action;
            String method;
            List<String> inputNames;
        }

        @Override
        protected void onPostExecute(String result) {
            resultTextView.setText(result);
        }
    }
}
