import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

export default function App() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>MTKey</CardTitle>
          <CardDescription>workbench scaffolding ready</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            The Tauri shell, toolchain and design tokens are in place. The
            cipher workbench UI lands in <code>src/app</code> and the crypto
            core in <code>src/core</code>.
          </p>
          <div>
            <Button variant="secondary">Scaffolding ready</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
