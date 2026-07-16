import { Alert } from '../services/api'

const getValue = (data: Record<string, any> | undefined | null, paths: string[]): string | null => {
  if (!data) return null

  for (const path of paths) {
    const value = path.split('.').reduce<any>((current, key) => current?.[key], data)
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return String(value)
    }
  }

  return null
}

export const getAlertRuleName = (alert: Alert): string =>
  alert.detection_rule?.name ||
  getValue(alert.ocsf_data, ['metadata.rule_name', 'rule.name', 'rule_name']) ||
  getValue(alert.raw_data, ['rule_name', 'detection_rule', 'signature']) ||
  'Detection rule'

export const getAlertClassName = (alert: Alert): string =>
  alert.ocsf_data?.class_name ||
  getValue(alert.ocsf_data, ['class', 'category_name']) ||
  'Security Finding'

export const getAlertActivityName = (alert: Alert): string =>
  alert.ocsf_data?.activity_name ||
  getValue(alert.ocsf_data, ['activity', 'activity_id']) ||
  'Rule Match'

export const getAlertMessage = (alert: Alert): string => {
  const message =
    alert.ocsf_data?.message ||
    getValue(alert.ocsf_data, ['finding_info.desc', 'finding_info.title', 'message']) ||
    getValue(alert.raw_data, ['message', 'description'])

  if (message) return message

  const image = getAlertProcessImage(alert)
  const command = getAlertCommandLine(alert)
  const reason = alert.why_matched || 'matched configured detection logic'

  if (image || command) {
    return `${getAlertRuleName(alert)} matched ${image || 'a process'}${command ? ` with command line "${command}"` : ''}: ${reason}.`
  }

  return `${getAlertRuleName(alert)} matched this event: ${reason}.`
}

export const getAlertProcessImage = (alert: Alert): string | null =>
  getValue(alert.ocsf_data, [
    'process.file.path',
    'process.name',
    'process',
    'image',
    'Image',
  ]) ||
  getValue(alert.raw_data, ['normalized_event.image', 'raw_event.Image', 'Image', 'image', 'process'])

export const getAlertParentImage = (alert: Alert): string | null =>
  getValue(alert.ocsf_data, ['process.parent_process.file.path', 'parent_process.file.path', 'parent_image']) ||
  getValue(alert.raw_data, ['normalized_event.parent_image', 'raw_event.ParentImage', 'ParentImage', 'parent_image'])

export const getAlertCommandLine = (alert: Alert): string | null =>
  getValue(alert.ocsf_data, [
    'process.cmd_line',
    'process.command_line',
    'command_line',
    'command',
    'CommandLine',
  ]) ||
  getValue(alert.raw_data, ['normalized_event.command_line', 'normalized_event.command', 'raw_event.CommandLine', 'CommandLine', 'command_line', 'command'])

export const getAlertHost = (alert: Alert): string | null =>
  getValue(alert.ocsf_data, ['device.hostname', 'device.name', 'hostname', 'host']) ||
  getValue(alert.raw_data, ['normalized_event.host', 'raw_event.Hostname', 'hostname', 'host'])

export const getAlertUser = (alert: Alert): string | null =>
  getValue(alert.ocsf_data, ['actor.user.name', 'user.name', 'user', 'account_name']) ||
  getValue(alert.raw_data, ['normalized_event.user', 'raw_event.SubjectUserName', 'raw_event.TargetUserName', 'user'])

export const getAlertMitre = (alert: Alert): string | null =>
  alert.detection_rule?.mitre_technique_id ||
  getValue(alert.ocsf_data, ['mitre.technique_id', 'attack.technique_id', 'technique_id']) ||
  getValue(alert.raw_data, ['mitre_technique_id', 'technique_id'])

export const getAlertProcessingState = (alert: Alert): string => {
  if (alert.processed_at) return 'Processed'
  if (alert.status === 'open' || alert.status === 'investigating') return 'Queued for analyst review'
  return alert.status
}
