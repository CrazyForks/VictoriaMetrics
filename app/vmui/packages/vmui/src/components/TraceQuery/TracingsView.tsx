import { FC, useState } from "preact/compat";
import Trace from "./Trace";
import Button from "../Main/Button/Button";
import { CodeIcon, CollapseIcon, DeleteIcon, DownloadIcon, ExpandIcon } from "../Main/Icons";
import "./style.scss";
import NestedNav from "./NestedNav/NestedNav";
import Alert from "../Main/Alert/Alert";
import Tooltip from "../Main/Tooltip/Tooltip";
import Modal from "../Main/Modal/Modal";
import JsonForm from "../../pages/TracePage/JsonForm/JsonForm";
import classNames from "classnames";
import useDeviceDetect from "../../hooks/useDeviceDetect";
import { downloadJSON } from "../../utils/file";

interface TraceViewProps {
  traces: Trace[];
  jsonEditor?: boolean;
  onDeleteClick: (trace: Trace) => void;
}

const TracingsView: FC<TraceViewProps> = ({ traces, jsonEditor = false, onDeleteClick }) => {
  const { isMobile } = useDeviceDetect();
  const [openTrace, setOpenTrace] = useState<Trace | null>(null);
  const [expandedTraces, setExpandedTraces] = useState<number[]>([]);

  const handleCloseJson = () => {
    setOpenTrace(null);
  };

  const handleUpdateTrace = (val: string, title: string) => {
    if (!jsonEditor || !openTrace) return;
    try {
      openTrace.setTracing(JSON.parse(val));
      openTrace.setQuery(title);
      setOpenTrace(null);
    } catch (e) {
      console.error(e);
    }
  };

  if (!traces.length) {
    return (
      <Alert variant="info">
        Please re-run the query to see results of the tracing
      </Alert>
    );
  }

  const handleDeleteClick = (tracingData: Trace) => () => {
    onDeleteClick(tracingData);
  };

  const handleJsonClick = (tracingData: Trace) => () => {
    setOpenTrace(tracingData);
  };

  const handleSaveToFile = (tracingData: Trace) => () => {
    downloadJSON(tracingData.originalJSON, `vmui_trace_${tracingData.queryValue}.json`);
  };

  const handleExpandAll = (tracingData: Trace) => () => {
    setExpandedTraces(prev => prev.includes(tracingData.idValue)
      ? prev.filter(n => n !== tracingData.idValue)
      : [...prev, tracingData.idValue]
    );
  };

  return (
    <>
      <div className="vm-tracings-view">
        {traces.map((trace: Trace) => (
          <div
            className="vm-tracings-view-trace vm-block vm-block_empty-padding"
            key={trace.idValue}
          >
            <div className="vm-tracings-view-trace-header">
              <h3 className="vm-tracings-view-trace-header-title">
              Trace for <b className="vm-tracings-view-trace-header-title__query">{trace.queryValue}</b>
              </h3>
              <Tooltip title={expandedTraces.includes(trace.idValue) ? "Collapse All" : "Expand All"}>
                <Button
                  variant="text"
                  startIcon={expandedTraces.includes(trace.idValue) ? <CollapseIcon/> : <ExpandIcon/> }
                  onClick={handleExpandAll(trace)}
                  ariaLabel={expandedTraces.includes(trace.idValue) ? "Collapse All" : "Expand All"}
                />
              </Tooltip>
              <Tooltip title={"Save Trace to JSON"}>
                <Button
                  variant="text"
                  startIcon={<DownloadIcon/>}
                  onClick={handleSaveToFile(trace)}
                  ariaLabel="Save trace to JSON"
                />
              </Tooltip>
              <Tooltip title={"Open JSON"}>
                <Button
                  variant="text"
                  startIcon={<CodeIcon/>}
                  onClick={handleJsonClick(trace)}
                  ariaLabel="open JSON"
                />
              </Tooltip>
              <Tooltip title={"Remove trace"}>
                <Button
                  variant="text"
                  color="error"
                  startIcon={<DeleteIcon/>}
                  onClick={handleDeleteClick(trace)}
                  ariaLabel="remove trace"
                />
              </Tooltip>
            </div>
            <nav
              className={classNames({
                "vm-tracings-view-trace__nav": true,
                "vm-tracings-view-trace__nav_mobile": isMobile
              })}
            >
              <NestedNav
                isRoot
                trace={trace}
                totalMsec={trace.duration}
                isExpandedAll={expandedTraces.includes(trace.idValue)}
              />
            </nav>
          </div>
        ))}
      </div>

      {openTrace && (
        <Modal
          title={openTrace.queryValue}
          onClose={handleCloseJson}
        >
          <JsonForm
            editable={jsonEditor}
            displayTitle={jsonEditor}
            defaultTile={openTrace.queryValue}
            defaultJson={openTrace.JSON}
            resetValue={openTrace.originalJSON}
            onClose={handleCloseJson}
            onUpload={handleUpdateTrace}
          />
        </Modal>
      )}
    </>
  );
};

export default TracingsView;
