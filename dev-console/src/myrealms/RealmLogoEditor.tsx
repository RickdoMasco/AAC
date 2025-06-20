import {
    BooleanInput,
    Create,
    Form,
    FunctionField,
    ImageField,
    ImageInput,
    LoadingIndicator,
    minLength,
    RecordContextProvider,
    ResourceContextProvider,
    SaveButton,
    Show,
    SimpleForm,
    SimpleShowLayout,
    TextInput,
    useDataProvider,
    TextField,
    useGetOne,
    useResourceContext,
    useRefresh,
    Button,
    useNotify,
    DeleteButton,
    DeleteWithConfirmButton,
} from 'react-admin';
import {
    DialogActions,
    Dialog,
    Stack,
    styled,
    Typography,
} from '@mui/material';
import { Page } from '../components/Page';
import { useRootSelector } from '@dslab/ra-root-selector';
import { MouseEventHandler, useEffect, useState } from 'react';
import {
    CreateInDialogButton,
    CreateInDialogButtonClasses,
} from '@dslab/ra-dialog-crud';
import AddIcon from '@mui/icons-material/Add';

export const RealmLogoEditor = () => {
    const { root: realmId } = useRootSelector();

    return (
        <ResourceContextProvider value={'realms/' + realmId}>
            <RealmLogoEditorComponent />
        </ResourceContextProvider>
    );
};

const RealmLogoEditorComponent = () => {
    const { root: realmId } = useRootSelector();
    const refresh = useRefresh();

    const upload = (data: any) => {
        console.log('upload', data);
        return false;
    };

    const onUpload = e => {
        refresh();
        e.stopPropagation();
    };

    return (
        <>
            <RealmLogoViewer />
            <RealmLogoUploader />
        </>
    );
};

const RealmLogoViewer = () => {
    const { root: realmId } = useRootSelector();
    const resource = useResourceContext();
    const notify = useNotify();
    const refresh = useRefresh();
    const dataProvider = useDataProvider();
    const { data: logo, isLoading } = useGetOne(resource, { id: 'logo' });

    // const [logo, setLogo] = useState<any | null>(null);
    // useEffect(() => {
    //     if (dataProvider) {
    //         dataProvider
    //             .invoke({ path: 'realms/' + realmId + '/logo' })
    //             .then(data => {
    //                 setLogo({ ...data, id: 'logo' });
    //             });
    //     }
    // }, [dataProvider]);

    if (!logo) {
        return <LoadingIndicator />;
    }

    return (
        <RecordContextProvider value={logo}>
            <SimpleShowLayout>
                {logo?.url ? (
                    <>
                        <ImageField source="url" title="name" />
                        <DeleteWithConfirmButton
                            redirect={false}
                            mutationOptions={{
                                onSuccess: () => {
                                    notify('ra.notification.deleted', {
                                        type: 'info',
                                    });
                                    refresh();
                                },
                            }}
                        />
                    </>
                ) : (
                    <Typography variant="body1">No logo set</Typography>
                )}
            </SimpleShowLayout>
        </RecordContextProvider>
    );
};

const RealmLogoUploader = () => {
    const dataProvider = useDataProvider();
    const { root: realmId } = useRootSelector();
    const refresh = useRefresh();
    const notify = useNotify();
    const [open, setOpen] = useState(false);
    const closeDialog = () => {
        setOpen(false);
    };

    const handleDialogOpen: MouseEventHandler<HTMLButtonElement> = e => {
        setOpen(true);
        e.stopPropagation();
    };

    const handleDialogClose: MouseEventHandler<HTMLButtonElement> = e => {
        closeDialog();
        e.stopPropagation();
    };

    const upload = (data: any) => {
        console.log('upload', data);
        if (!data.file) {
            notify('No file selected', { type: 'warning' });
            return false;
        }

        //build form data
        const formData = new FormData();
        formData.append('file', data.file.rawFile);

        //upload
        dataProvider
            .invoke({
                path: 'realms/' + realmId + '/logo',
                body: formData,
                options: {
                    method: 'POST',
                },
            })
            .then(json => {
                closeDialog();
                if (json) {
                    notify('ra.notification.created', { type: 'info' });
                    refresh();
                } else {
                    notify('ra.notification.bad_item', { type: 'warning' });
                }
            })
            .catch(error => {
                const msg = error.message || 'ra.notification.error';
                notify(msg, { type: 'error' });
            });
    };

    const onUpload = e => {
        refresh();
        e.stopPropagation();
    };

    return (
        <>
            <Button
                label={'action.upload'}
                onClick={handleDialogOpen}
                className={CreateInDialogButtonClasses.button}
                variant="contained"
            >
                <AddIcon />
            </Button>
            <CreateDialog
                maxWidth={'sm'}
                onClose={handleDialogClose}
                aria-labelledby="create-dialog-title"
                open={open}
                className={CreateInDialogButtonClasses.dialog}
                scroll="paper"
            >
                <RecordContextProvider value={{ id: realmId }}>
                    <SimpleForm
                        onSubmit={upload}
                        toolbar={
                            <DialogActions>
                                <SaveButton variant="text" label="upload" />
                            </DialogActions>
                        }
                    >
                        <ImageInput
                            source="file"
                            label="Logo"
                            accept="image/*"
                            maxSize={256 * 1024}
                            fullWidth
                        >
                            {/* <TextField source="title" /> */}
                            <ImageField source="src" title="logo" />
                        </ImageInput>
                    </SimpleForm>
                </RecordContextProvider>
            </CreateDialog>
        </>
    );
};

const CreateDialog = styled(Dialog, {
    name: 'LogoUploader',
    overridesResolver: (_props, styles) => styles.root,
})(({ theme }) => ({
    [`& .${CreateInDialogButtonClasses.title}`]: {
        padding: theme.spacing(0),
    },
    [`& .${CreateInDialogButtonClasses.header}`]: {
        padding: theme.spacing(2, 2),
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
    },
    [`& .${CreateInDialogButtonClasses.closeButton}`]: {
        height: 'fit-content',
    },
}));
