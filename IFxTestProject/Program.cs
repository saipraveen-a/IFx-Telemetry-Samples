using System;
using Microsoft.Cloud.InstrumentationFramework;

namespace IFxTestProject
{
    class Program
    {
        static void Main(string[] args)
        {
            EmitMetrics();

            // IFx initialization is a required step for emitting logs
            IfxInitializer.Initialize(
                "cloudAgentTenantIdentity",
                "cloudAgentRoleIdentity",
                "cloudAgentRoleInstanceIdentity");

            EmitLogs();
        }

        static void EmitMetrics()
        {
            ErrorContext mdmError = new ErrorContext();

            MeasureMetric1D testMeasure = MeasureMetric1D.Create(
                "MyMonitoringAccount",
                "MyMetricNamespace",
                "MyMetricName",
                "MyDimensionName",
                ref mdmError);

            if (testMeasure == null)
            {
                Console.WriteLine("Fail to create MeasureMetric, error code is {0:X}, error message is {1}",
                    mdmError.ErrorCode,
                    mdmError.ErrorMessage);
            }
            else if (!testMeasure.LogValue(101, "MyDimensionValue", ref mdmError))
            {
                Console.WriteLine("Fail to log MeasureMetric value, error code is {0:X}, error message is {1}",
                    mdmError.ErrorCode,
                    mdmError.ErrorMessage);
            }
        }

        static void EmitLogs()
        {
            using (Operation operation = new Operation("Some Operation"))
            {
                operation.SetResult(OperationResult.Success);
            }
        }
    }
}
