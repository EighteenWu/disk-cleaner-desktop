use crate::automation_storage::{AutomationCadence, AutomationConfig};
use cleaner_core::AutomationTrigger;
use serde::Serialize;
use std::{fs, path::Path, process::Command};
use uuid::Uuid;

const STARTUP_TASK_NAME: &str = r"\CleanDeck\StartupAutomation";
const SCHEDULE_TASK_NAME: &str = r"\CleanDeck\ScheduledAutomation";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerStatus {
    pub startup_registered: bool,
    pub schedule_registered: bool,
}

pub fn reconcile_tasks(
    executable: &Path,
    config: &AutomationConfig,
    token: Uuid,
) -> Result<SchedulerStatus, String> {
    validate_executable(executable)?;
    if config.startup_enabled {
        create_task(
            executable,
            config,
            token,
            STARTUP_TASK_NAME,
            AutomationTrigger::Startup,
        )?;
    } else {
        delete_task(STARTUP_TASK_NAME)?;
    }
    if config.schedule_enabled {
        create_task(
            executable,
            config,
            token,
            SCHEDULE_TASK_NAME,
            AutomationTrigger::Scheduled,
        )?;
    } else {
        delete_task(SCHEDULE_TASK_NAME)?;
    }
    query_status()
}

pub fn remove_tasks() -> Result<(), String> {
    let startup = delete_task(STARTUP_TASK_NAME);
    let schedule = delete_task(SCHEDULE_TASK_NAME);
    startup.and(schedule)
}

pub fn query_status() -> Result<SchedulerStatus, String> {
    Ok(SchedulerStatus {
        startup_registered: task_exists(STARTUP_TASK_NAME)?,
        schedule_registered: task_exists(SCHEDULE_TASK_NAME)?,
    })
}

fn create_task(
    executable: &Path,
    config: &AutomationConfig,
    token: Uuid,
    task_name: &str,
    trigger: AutomationTrigger,
) -> Result<(), String> {
    let trigger_value = match trigger {
        AutomationTrigger::Startup => "startup",
        AutomationTrigger::Scheduled => "scheduled",
        AutomationTrigger::Manual => return Err("手工运行不注册计划任务。".into()),
    };
    let xml = task_xml(executable, config, token, trigger)?;
    let xml_path = std::env::temp_dir().join(format!("cleandeck-task-{}.xml", Uuid::new_v4()));
    fs::write(&xml_path, xml).map_err(|error| format!("写入计划任务定义失败：{error}"))?;
    let args = vec![
        "/Create".to_string(),
        "/F".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
        "/XML".to_string(),
        xml_path.to_string_lossy().into_owned(),
    ];
    let result = run_schtasks(&args, &format!("注册 {trigger_value} 自动化任务"));
    let _ = fs::remove_file(xml_path);
    result
}

fn task_xml(
    executable: &Path,
    config: &AutomationConfig,
    token: Uuid,
    trigger: AutomationTrigger,
) -> Result<String, String> {
    validate_executable(executable)?;
    let executable = xml_escape(
        executable
            .to_str()
            .ok_or_else(|| "应用路径编码无效。".to_string())?,
    );
    let trigger_value = match trigger {
        AutomationTrigger::Startup => "startup",
        AutomationTrigger::Scheduled => "scheduled",
        AutomationTrigger::Manual => return Err("手工运行不注册计划任务。".into()),
    };
    let trigger_xml = match trigger {
        AutomationTrigger::Startup => {
            "<LogonTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></LogonTrigger>".to_string()
        }
        AutomationTrigger::Scheduled => scheduled_trigger_xml(config)?,
        AutomationTrigger::Manual => unreachable!(),
    };
    let arguments = xml_escape(&format!(
        "--background-task {} --task-id {trigger_value} --config-id {} --run-token {}",
        mode_value(config),
        config.config_id,
        token
    ));
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>CleanDeck</Author><Description>CleanDeck local automation</Description></RegistrationInfo>
  <Triggers>{trigger_xml}</Triggers>
  <Principals><Principal id="Author"><GroupId>S-1-5-32-544</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowHardTerminate>true</AllowHardTerminate><Enabled>true</Enabled><ExecutionTimeLimit>PT{}S</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>{executable}</Command><Arguments>{arguments}</Arguments></Exec></Actions>
</Task>"#,
        config.limits.max_runtime_seconds
    ))
}

fn scheduled_trigger_xml(config: &AutomationConfig) -> Result<String, String> {
    let start_boundary = format!(
        "{}T{}:00",
        chrono::Local::now().format("%Y-%m-%d"),
        config.local_time
    );
    let schedule = match config.cadence {
        AutomationCadence::Daily => "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>".to_string(),
        AutomationCadence::Weekly => format!(
            "<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><{}/></DaysOfWeek></ScheduleByWeek>",
            weekday_xml(config.weekday.ok_or_else(|| "每周任务缺少星期。".to_string())?)?
        ),
    };
    Ok(format!(
        "<CalendarTrigger><StartBoundary>{start_boundary}</StartBoundary><Enabled>true</Enabled><ScheduleByDayPlaceholder/>{schedule}</CalendarTrigger>"
    ).replace("<ScheduleByDayPlaceholder/>", ""))
}

fn delete_task(task_name: &str) -> Result<(), String> {
    let args = ["/Delete", "/F", "/TN", task_name];
    let output = Command::new("schtasks.exe")
        .args(args)
        .output()
        .map_err(|error| format!("启动任务计划程序失败：{error}"))?;
    if output.status.success() || !task_exists(task_name)? {
        Ok(())
    } else {
        Err("删除计划任务失败。".into())
    }
}

fn task_exists(task_name: &str) -> Result<bool, String> {
    let output = Command::new("schtasks.exe")
        .args(["/Query", "/TN", task_name])
        .output()
        .map_err(|error| format!("查询任务计划程序失败：{error}"))?;
    Ok(output.status.success())
}

fn run_schtasks(args: &[String], operation: &str) -> Result<(), String> {
    let output = Command::new("schtasks.exe")
        .args(args)
        .output()
        .map_err(|error| format!("{operation}失败：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let code = output.status.code().unwrap_or(-1);
        Err(format!("{operation}失败（退出码 {code}）。"))
    }
}

fn validate_executable(path: &Path) -> Result<(), String> {
    let value = path
        .to_str()
        .ok_or_else(|| "应用路径编码无效。".to_string())?;
    if !path.is_absolute()
        || value.contains('"')
        || value.chars().any(char::is_control)
        || !value.to_ascii_lowercase().ends_with(".exe")
    {
        return Err("应用可执行文件路径无效。".into());
    }
    Ok(())
}

fn mode_value(config: &AutomationConfig) -> &'static str {
    match config.mode {
        cleaner_core::AutomationMode::ScanOnly => "scan",
        cleaner_core::AutomationMode::ScanAndCleanup => "cleanup",
    }
}

fn weekday_xml(weekday: u8) -> Result<&'static str, String> {
    match weekday {
        1 => Ok("Monday"),
        2 => Ok("Tuesday"),
        3 => Ok("Wednesday"),
        4 => Ok("Thursday"),
        5 => Ok("Friday"),
        6 => Ok("Saturday"),
        7 => Ok("Sunday"),
        _ => Err("每周任务星期无效。".into()),
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_validation_rejects_argument_injection() {
        assert!(validate_executable(Path::new(r#"C:\Apps\CleanDeck\clean.exe\" --bad"#)).is_err());
        assert!(validate_executable(Path::new(r"C:\Apps\CleanDeck\clean.exe")).is_ok());
    }

    #[test]
    fn task_xml_enforces_runner_limits_and_safe_arguments() {
        let config = AutomationConfig {
            schedule_enabled: true,
            cadence: AutomationCadence::Weekly,
            weekday: Some(7),
            ..AutomationConfig::default()
        };
        let xml = task_xml(
            Path::new(r"C:\Apps\CleanDeck\clean.exe"),
            &config,
            Uuid::nil(),
            AutomationTrigger::Scheduled,
        )
        .expect("task xml");
        assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        assert!(xml.contains("<StartWhenAvailable>true</StartWhenAvailable>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT900S</ExecutionTimeLimit>"));
        assert!(xml.contains("<Sunday/>"));
        assert!(xml.contains("--config-id"));
    }

    #[test]
    fn weekday_mapping_is_stable() {
        assert_eq!(weekday_xml(1), Ok("Monday"));
        assert_eq!(weekday_xml(7), Ok("Sunday"));
        assert!(weekday_xml(0).is_err());
    }
}
