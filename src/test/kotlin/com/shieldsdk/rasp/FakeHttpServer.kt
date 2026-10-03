package com.shieldsdk.rasp

import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections

/**
 * Minimal HTTP/1.1 server on a real 127.0.0.1 socket for JVM tests
 * (`com.sun.net.httpserver` is not on the Android unit-test classpath).
 * Records every request and answers with the status [respond] returns and
 * the body [bodyFor] returns (empty by default).
 */
class FakeHttpServer(
    private val bodyFor: (Request) -> String = { "" },
    private val respond: (Request) -> Int,
) : AutoCloseable {

    data class Request(val method: String, val path: String, val headers: Map<String, String>, val body: String)

    private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = socket.localPort
    val baseUrl: String get() = "http://127.0.0.1:$port"
    val requests: MutableList<Request> = Collections.synchronizedList(mutableListOf())

    init {
        Thread {
            while (!socket.isClosed) {
                val client = try { socket.accept() } catch (e: IOException) { break }
                client.use { handle(it) }
            }
        }.apply { isDaemon = true; start() }
    }

    private fun handle(client: Socket) {
        val input = BufferedInputStream(client.getInputStream())
        val requestLine = readLine(input).split(" ")
        val headers = mutableMapOf<String, String>()
        while (true) {
            val line = readLine(input)
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx > 0) headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
        }
        val length = headers["content-length"]?.toInt() ?: 0
        val body = ByteArray(length)
        var read = 0
        while (read < length) {
            val n = input.read(body, read, length - read)
            if (n < 0) break
            read += n
        }
        val request = Request(requestLine.getOrElse(0) { "" }, requestLine.getOrElse(1) { "" }, headers, String(body, Charsets.UTF_8))
        requests.add(request)
        val status = respond(request)
        val responseBody = bodyFor(request).toByteArray(Charsets.UTF_8)
        client.getOutputStream().apply {
            write("HTTP/1.1 $status Test\r\nContent-Type: application/json\r\nContent-Length: ${responseBody.size}\r\nConnection: close\r\n\r\n".toByteArray())
            write(responseBody)
            flush()
        }
    }

    private fun readLine(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0 || c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    override fun close() = socket.close()
}
