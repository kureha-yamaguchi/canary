import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-purple-50 to-white">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-12">
          <h1 className="text-6xl font-bold text-purple-700 mb-4">
            Mediocre Magic Academy
          </h1>
          <p className="text-2xl text-gray-600">
            Where wizards learn to be just okay
          </p>
        </div>

        <div className="max-w-4xl mx-auto grid gap-8 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Our Philosophy</CardTitle>
              <CardDescription>Excellence is overrated</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-gray-700">
                At Mediocre Magic Academy, we believe that not every wizard needs to be
                extraordinary. Our curriculum focuses on teaching practical spells that work
                most of the time, with acceptable side effects.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Programs Offered</CardTitle>
              <CardDescription>Moderately impressive courses</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="list-disc list-inside text-gray-700 space-y-2">
                <li>Potion Brewing (70% success rate)</li>
                <li>Levitation (objects under 5 lbs)</li>
                <li>Basic Divination (tomorrow&apos;s weather only)</li>
                <li>Spell Casting (minor inconveniences specialty)</li>
              </ul>
            </CardContent>
          </Card>
        </div>

        <div className="text-center mt-12">
          <Card className="max-w-2xl mx-auto">
            <CardHeader>
              <CardTitle>Ready to Be Mediocre?</CardTitle>
              <CardDescription>
                Join hundreds of adequately trained wizards
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-gray-700 mb-6">
                Submit your application to our admissions team. We review applications
                on a first-come, first-served basis and accept most applicants.
              </p>
              <Link href="/contact">
                <Button size="lg" className="text-lg">
                  Apply Now
                </Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
