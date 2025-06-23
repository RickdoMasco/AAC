import {
    downloadJson,
    downloadYaml,
    ExportRecordButton,
    ExportRecordButtonProps,
    toJson,
    toYaml,
} from '@dslab/ra-export-record-button';
import { useEffect, useRef, useState } from 'react';
import {
    Button,
    useRecordContext,
    fetchRelatedRecords,
    useResourceContext,
    useDataProvider,
} from 'react-admin';
import SettingsBackupRestoreIcon from '@mui/icons-material/SettingsBackupRestore';
import { useRootSelector } from '@dslab/ra-root-selector';

const defaultIcon = <SettingsBackupRestoreIcon />;

export const BackupExportButton = (props: ExportRecordButtonProps) => {
    const {
        label = 'action.backup',
        icon = defaultIcon,
        language = 'yaml',
        color = 'info',
        exporter,
        filename,
        record: recordProp,
        resource: resourceProp,
        ...rest
    } = props;
    const dataProvider = useDataProvider();
    const { root: realmId } = useRootSelector();

    const record = useRecordContext(props);
    const resource = useResourceContext(props);
    const isLoading = useRef<boolean>(false);

    const handleExport = e => {
        if (!isLoading.current && record && dataProvider) {
            isLoading.current = true;
            dataProvider
                .invoke({ path: resource + '/' + realmId + '/backup' })
                .then(data => {
                    if (data) {
                        if (exporter) {
                            exporter(
                                [data],
                                fetchRelatedRecords(dataProvider),
                                dataProvider,
                                resource
                            );
                        } else {
                            const name =
                                filename || `${resource}-${record.id}-backup`;
                            if (language === 'yaml') {
                                downloadYaml(toYaml(data), name);
                            } else if (language === 'json') {
                                downloadJson(toJson(data), name);
                            }
                        }
                    }
                })
                .catch(error => {
                    console.error('Export failed:', error);
                });
        }

        e.stopPropagation();
    };

    return (
        <Button label={label} onClick={handleExport} {...rest}>
            {icon}
        </Button>
    );
};
