namespace OpenCIFS.Client
{
    internal sealed class OpenCifsClientConnectionServices
    {
        public OpenCifsClientConnectionServices(
            OpenCifsClientAdministrationService administrationService,
            OpenCifsClientCompoundOperationService compoundOperationService,
            OpenCifsClientConnectionControlService controlService,
            OpenCifsClientFileOperationService fileOperationService,
            OpenCifsClientConnectionLifecycleService lifecycleService,
            OpenCifsClientConnectionStateService stateService,
            OpenCifsClientTreeConnectionService treeConnectionService,
            OpenCifsClientTreeOpenOperationService treeOpenOperationService)
        {
            AdministrationService = administrationService;
            CompoundOperationService = compoundOperationService;
            ControlService = controlService;
            FileOperationService = fileOperationService;
            LifecycleService = lifecycleService;
            StateService = stateService;
            TreeConnectionService = treeConnectionService;
            TreeOpenOperationService = treeOpenOperationService;
        }

        public OpenCifsClientAdministrationService AdministrationService { get; }

        public OpenCifsClientCompoundOperationService CompoundOperationService { get; }

        public OpenCifsClientConnectionControlService ControlService { get; }

        public OpenCifsClientFileOperationService FileOperationService { get; }

        public OpenCifsClientConnectionLifecycleService LifecycleService { get; }

        public OpenCifsClientConnectionStateService StateService { get; }

        public OpenCifsClientTreeConnectionService TreeConnectionService { get; }

        public OpenCifsClientTreeOpenOperationService TreeOpenOperationService { get; }
    }
}
