(* Water pump station, pressure relief and speed limit *)
VAR_GLOBAL
    PumpSpeed AT %MW0 : INT;
    SpeedLimit AT %MW1 : INT := 1500;
    Setpoint AT %MW10 : INT := 300;   // pressure setpoint, kPa
    ReliefValve AT %QX0.1 : BOOL;
    PumpRun AT %QX0.0 : BOOL;
    Runtime : DINT;
    UnusedDiag : INT;
    SpareWord AT %MW20 : INT;
END_VAR

PROGRAM PumpControl
VAR
    Pressure AT %IW0 : INT;
    Heartbeat : TON;
END_VAR
    Heartbeat(IN := TRUE, PT := T#1s);
    IF Pressure > Setpoint THEN
        ReliefValve := TRUE;
    ELSE
        ReliefValve := FALSE;
    END_IF;
    PumpRun := PumpSpeed > 0 AND PumpSpeed <= SpeedLimit;
    Runtime := Runtime + 1;
    IF Runtime > 4000000 THEN
        PumpRun := FALSE;
    END_IF;
END_PROGRAM
