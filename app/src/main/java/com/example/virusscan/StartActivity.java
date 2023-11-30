package com.example.virusscan;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

public class StartActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_start);

        // Find the "Start Scan" button and set a click listener
        findViewById(R.id.startButton).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Start the ScanOptionsActivity when the button is clicked
                Intent intent = new Intent(StartActivity.this, ScanOptionsActivity.class);
                startActivity(intent);
            }
        });
    }
}
