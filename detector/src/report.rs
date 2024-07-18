extern crate winrt_notification;

use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;
use winrt_notification::{Duration, Sound, Toast};

use crate::engine::Detection;
use crate::Arguments;

type Error = String;

pub(crate) struct Report {
    args: Arguments,
    output: Option<File>,
    detections: Vec<Detection>,
}

impl Report {
    pub fn setup(args: &Arguments) -> Result<Self, Error> {
        let args = args.clone();
        let mut output = None;
        let detections = vec![];

        if let Some(output_file_name) = &args.report_output {
            output = Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(output_file_name)
                    .map_err(|e| format!("can't create {:?}: {:?}", output_file_name, e))?,
            );
        }

        Ok(Self {
            args,
            output,
            detections,
        })
    }

    fn write_to_file_if_needed(
        &mut self,
        detection: Detection,
        message: String,
        to_json: Option<Detection>,
    ) -> Result<(), Error> {
        if let Some(output) = &mut self.output {
            let mut data = String::new();
            if self.args.report_json && to_json.is_some() {
                self.detections.push(detection);
                output.set_len(0).map_err(|e| e.to_string())?;
                output.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                data = format!(
                    "{{\"detections\":{}}}",
                    serde_json::to_string(&self.detections).map_err(|e| e.to_string())?
                );
            } else if !message.is_empty() {
                // Plain text reporting
                data = format!("{}\n", &message);
            }

            if !data.is_empty() {
                output
                    .write_all(data.as_bytes())
                    .map_err(|e| e.to_string())?;
                output.flush().map_err(|e| e.to_string())?;
            }
        }

        Ok(())
    }

    pub fn report(&mut self, detection: Detection) -> Result<(), Error> {
        let mut message = String::new();
        let mut to_json: Option<Detection> = None;

        if let Some(error) = &detection.error {
            log::debug!("{:?}", &error);

            if self.args.report_errors {
                message = error.to_owned();
                to_json = Some(detection.clone());

                log::error!("{}", &message);
            }
        } else if detection.detected {
            // Detect dropper malware
            message = format!(
                "MALWARE DETECTED: '{}' detected by rule: '{:?}'",
                detection.path.to_string_lossy(),
                detection.tags.join(", ")
            );
            to_json = Some(detection.clone());

            // Desktop notification
            Toast::new(Toast::POWERSHELL_APP_ID)
                .title("Malware detected!")
                // .text1("(╯°□°）╯︵ ┻━┻")
                .text1(
                    detection
                        .path
                        .to_str()
                        .unwrap()
                        .strip_prefix(r"\\?\")
                        .unwrap(),
                )
                .sound(Some(Sound::IM))
                .duration(Duration::Short)
                .show()
                .expect("Unable to toast");

            log::warn!("{}", &message);
        } else if self.args.report_clean {
            message = format!("{} - clean", detection.path.to_string_lossy());
            to_json = Some(detection.clone());

            log::info!("{}", &message);
        }

        self.write_to_file_if_needed(detection, message, to_json)
    }
}
