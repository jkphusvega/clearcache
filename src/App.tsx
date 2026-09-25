// M1: title and an empty folder table. Columns follow SPEC.md "4. 메인 화면".
const COLUMNS = ["이름", "경로", "크기", "등급", "근거", "출처"] as const;

function App() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white px-6 py-4">
        <h1 className="text-xl font-semibold tracking-tight">ClearCache</h1>
        <p className="mt-0.5 text-sm text-slate-500">
          큰 폴더를 찾아 지워도 되는지 판정하고, 고른 것만 격리합니다.
        </p>
      </header>

      <main className="flex-1 p-6">
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          <table className="w-full table-fixed text-left text-sm">
            <thead className="bg-slate-100 text-xs font-medium text-slate-600">
              <tr>
                <th className="w-10 px-3 py-2">
                  <input type="checkbox" disabled aria-label="전체 선택" />
                </th>
                {COLUMNS.map((col) => (
                  <th key={col} className="px-3 py-2">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan={COLUMNS.length + 1} className="px-3 py-16 text-center text-slate-400">
                  아직 스캔한 폴더가 없습니다.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}

export default App;
