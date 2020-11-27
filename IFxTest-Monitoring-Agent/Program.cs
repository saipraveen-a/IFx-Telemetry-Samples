using System;
using Microsoft.Cloud.InstrumentationFramework;

namespace IFxTest_MA
{
    class Program
    {
        static void Main(string[] args)
        {
            EmitMetrics();

            // IFx initialization is a required step for emitting logs
            IfxInitializer.Initialize("ifxsession");

            EmitOperations();
            EmitLogs();
        }

        private static void EmitLogs()
        {
            IfxTracer.LogMessage(
            IfxTracingLevel.Critical, // The trace level of this trace message.
            "ComponentFoo", // Tag Id: This parameter can be used for identifying and grouping the source of the instrumentation point. e.g. at component, class or  file level.
                            // You can potentially use the value of this value to retrieve message emitted from particular parts of the source code in log search.
            "A critical message."); // The message being logged. 
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

        static void EmitOperations()
        {
            using (Operation operation = new Operation("Some Operation"))
            {
                operation.SetResult(OperationResult.Success);
            }
        }
    }
}
