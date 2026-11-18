
// ruleid: vs-js-react-html
const a = <div dangerouslySetInnerHTML={{__html: value}} />;
// ok: vs-js-react-html
const b = <div>{value}</div>;
